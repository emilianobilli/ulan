#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <linux/wait.h>
#include <linux/fs.h>  
#include <linux/fcntl.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/net_tstamp.h>
#include <linux/ip.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>
#include <linux/version.h>
/*
 * This part defines a transmit queue tailored for sk_buff data structures.
 * The purpose of this queue is to enable safe buffering of packets (skb's)
 * for transmission in a kernel context, providing thread safety through
 * mutex locks.
 *
 * Key components:
 * - xmit_len: Counter that tracks the number of skb's currently in the queue.
 * - xmit_mutex: Mutex lock ensuring thread safety during enqueue and dequeue operations.
 * - xmit_head: The head of the sk_buff linked list.
 *
 * Functions:
 * - dequeue(): Safely removes and returns an skb from the front of the queue.
 * - enqueue(): Safely adds an skb to the end of the queue and updates xmit_len.
 * - queue_len(): Safely retrieves the current number of skb's in the queue.
 *
 *
 * Usage:
 * Callers should use enqueue() to add sk_buff's to the queue and 
 * dequeue() to remove and obtain sk_buff's from the queue. The queue_len()
 * function can be used to query the current length of the queue. All 
 * operations are thread-safe.
 */

static struct {
    size_t              xmit_len;
    struct mutex        xmit_mutex;
    struct sk_buff_head xmit_head;
} xmit_queue;

static DECLARE_WAIT_QUEUE_HEAD(ulan_read_wait_queue);

static struct sk_buff *dequeue(void)  {
    struct sk_buff *skb = NULL;

    mutex_lock(&xmit_queue.xmit_mutex);
    skb = __skb_dequeue(&xmit_queue.xmit_head);
    if (likely(skb)) {
        xmit_queue.xmit_len--;
    }
    mutex_unlock(&xmit_queue.xmit_mutex);
    
    return skb;
}

static void enqueue(struct sk_buff *skb) {
    mutex_lock(&xmit_queue.xmit_mutex);

    __skb_queue_tail(&xmit_queue.xmit_head, skb);
    xmit_queue.xmit_len++;

    mutex_unlock(&xmit_queue.xmit_mutex);
}

static size_t queue_len(void) {
    size_t len;
    mutex_lock(&xmit_queue.xmit_mutex);
    len = xmit_queue.xmit_len;
    mutex_unlock(&xmit_queue.xmit_mutex);
    return len;
}

static void push(struct sk_buff *skb) {
    mutex_lock(&xmit_queue.xmit_mutex);

    __skb_queue_head(&xmit_queue.xmit_head, skb);
    xmit_queue.xmit_len++;

    mutex_unlock(&xmit_queue.xmit_mutex);
}

static void clean_xmit_queue(void) {
    struct sk_buff *skb;

    while ((skb = dequeue()) != NULL) {
        dev_kfree_skb(skb);
    }
}

/*===========================================================================================*
 * Fake ethernet driver. /dev/ulan0															 *
 *===========================================================================================*/
static struct net_device *dev_ulan;
#define IFNAME     "ulan"
#define IFVERSION  "1.0"
#define CARRIER_ON  1
#define CARRIER_OFF 0

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
struct pcpu_dstats {
    u64			tx_packets;
    u64			tx_bytes;
    u64         rx_packets;
    u64         rx_bytes;
    struct u64_stats_sync	syncp;
};
#endif

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev) {}

static int is_ipframe(struct sk_buff *skb) {
    struct ethhdr *eth = eth_hdr(skb);
    if (ntohs(eth->h_proto) !=  ETH_P_IP) 
        return 0;
    return 1;
}

static void ulan_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats) {
    int i;

    for_each_possible_cpu(i) {
        const struct pcpu_dstats *dstats;
        u64 bytes_tx, packets_tx, bytes_rx, packets_rx;
        unsigned int start;

        dstats = per_cpu_ptr(dev->dstats, i);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
        do {
            start = u64_stats_fetch_begin(&dstats->syncp);
            bytes_tx   = dstats->tx_bytes;
            packets_tx = dstats->tx_packets;
            bytes_rx   = dstats->rx_bytes;
            packets_rx = dstats->rx_packets;
        } while (u64_stats_fetch_retry(&dstats->syncp, start));
#else
        do {
            start = u64_stats_fetch_begin_irq(&dstats->syncp);
            bytes_tx   = dstats->tx_bytes;
            packets_tx = dstats->tx_packets;
            bytes_rx   = dstats->rx_bytes;
            packets_rx = dstats->rx_packets;
        } while (u64_stats_fetch_retry_irq(&dstats->syncp, start));
#endif
        stats->tx_bytes   += bytes_tx;
        stats->tx_packets += packets_tx;
        stats->rx_bytes   += bytes_tx;
        stats->rx_packets += bytes_rx;
    }
}

static int ulan_dev_init(struct net_device *dev) {
    dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
    if (!dev->dstats)
        return -ENOMEM;

    return 0;
}

static void ulan_dev_uninit(struct net_device *dev) {
    free_percpu(dev->dstats);
}

static netdev_tx_t ulan_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

    if (!netif_carrier_ok(dev)) {
        dev_kfree_skb(skb);
        return NETDEV_TX_BUSY;
    }

    if (!is_ipframe(skb)) {
        dev_kfree_skb(skb);
        goto out;
    }

    u64_stats_update_begin(&dstats->syncp);
    dstats->tx_packets++;
    dstats->tx_bytes += skb->len;
    u64_stats_update_end(&dstats->syncp);

    skb_tx_timestamp(skb);
    enqueue(skb);
    wake_up_interruptible(&ulan_read_wait_queue);
out:
    return NETDEV_TX_OK;
}

static int ulan_change_carrier(struct net_device *dev, bool new_carrier) {
    if (new_carrier)
        netif_carrier_on(dev);
    else
        netif_carrier_off(dev);
    return 0;
}

static const struct net_device_ops ulan_netdev_ops = {
    .ndo_init		        = ulan_dev_init,
    .ndo_uninit		        = ulan_dev_uninit,
    .ndo_start_xmit		    = ulan_xmit,
    .ndo_validate_addr	    = eth_validate_addr,
    .ndo_set_rx_mode	    = set_multicast_list,
    .ndo_set_mac_address	= eth_mac_addr,
    .ndo_get_stats64	    = ulan_get_stats64,
};

static void ulan_get_drvinfo(struct net_device *dev,
                  struct ethtool_drvinfo *info)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    strscpy(info->driver, IFNAME, sizeof(info->driver));
    strscpy(info->version, IFVERSION, sizeof(info->version));
#else
    strlcpy(info->driver, IFNAME, sizeof(info->driver));
    strlcpy(info->version, IFVERSION, sizeof(info->version));
#endif
}

static const struct ethtool_ops ulan_ethtool_ops = {
    .get_drvinfo       	= ulan_get_drvinfo,
    .get_ts_info		= ethtool_op_get_ts_info,
};

static void ulan_setup(struct net_device *dev) {
    ether_setup(dev);

    /* Initialize the device structure. */
    dev->netdev_ops = &ulan_netdev_ops;
    dev->ethtool_ops = &ulan_ethtool_ops;
    dev->needs_free_netdev = true;

    /* Fill in device structure with ethernet-generic values. */
    dev->flags |= IFF_NOARP;
    dev->flags &= ~IFF_MULTICAST;
    dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
    dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST;
    dev->features	|= NETIF_F_ALL_TSO;
    dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
    dev->features	|= NETIF_F_GSO_ENCAP_ALL;
    dev->hw_features |= dev->features;
    dev->hw_enc_features |= dev->features;
    eth_hw_addr_random(dev);

    dev->mtu = 1442; /* 1514 - Ethernet(14) - IP(20) - UDP(8) - sdlt(30) */
}

static int ulan_validate(struct nlattr *tb[], struct nlattr *data[],
              struct netlink_ext_ack *extack) {
    if (tb[IFLA_ADDRESS]) {
        if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
            return -EINVAL;
        if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
            return -EADDRNOTAVAIL;
    }
    return 0;
}

static struct rtnl_link_ops ulan_link_ops __read_mostly = {
    .kind		= IFNAME,
    .setup		= ulan_setup,
    .validate	= ulan_validate,
};

static int __init ulan_init_one(void) {
    int err;

    dev_ulan = alloc_netdev(0, "ulan%d", NET_NAME_ENUM, ulan_setup);
    if (!dev_ulan)
        return -ENOMEM;

    dev_ulan->rtnl_link_ops = &ulan_link_ops;
    err = register_netdevice(dev_ulan);
    if (err < 0)
        goto err;
    return 0;

err:
    free_netdev(dev_ulan);
    return err;
}

/*===========================================================================================*
 * Misc Character Device. /dev/ulan_io														 *
 *===========================================================================================*/
#define FALSE 0
#define TRUE  1
static atomic_t device_open = ATOMIC_INIT(0);

#define DEVICE_NAME "ulan_io"

static ssize_t ulan_io_write(struct file *filp, const char __user *ubuf, size_t count, loff_t *off) {
    struct pcpu_dstats *dstats = this_cpu_ptr(dev_ulan->dstats);
    struct sk_buff *skb;

    if (!netif_carrier_ok(dev_ulan))
        return -EFAULT;

    skb = netdev_alloc_skb(dev_ulan, count);
    if (!unlikely(skb))
        return -ENOMEM;

    skb_put(skb, count);
    if (copy_from_user(skb->data, ubuf, count)) {
        dev_kfree_skb(skb);
        return -EFAULT;
    }

    skb->len = count;
    // Establecer que estamos manejando un paquete IP
    skb->protocol = htons(ETH_P_IP);  // Protocolo IPv4
    skb->dev = dev_ulan;              // Asociar con el dispositivo de red
    skb->pkt_type = PACKET_HOST;      // Configurar como paquete destinado a este host

    // Establecer que el paquete ya tiene una cabecera IP
    skb_reset_network_header(skb);

    // Inyectar el paquete IP directamente en la pila IP usando netif_rx
    if (netif_rx(skb) != NET_RX_SUCCESS) {
        dev_kfree_skb(skb);
        return -EFAULT;
    }

    u64_stats_update_begin(&dstats->syncp);
    dstats->rx_packets++;
    dstats->rx_bytes += skb->len;
    u64_stats_update_end(&dstats->syncp);

    return count;
}


/* 
 * Reads a packet from the queue, considering both non-blocking and blocking scenarios.
 */
static ssize_t ulan_io_read(struct file *flip, char __user *buf, size_t count, loff_t *off) {
    struct sk_buff *skb;
    ssize_t ret;

    /* If there are packets in the queue, proceed to read. */
    if (queue_len() > 0)
        goto read;
    
    if (flip->f_flags & O_NONBLOCK) {
        ret = -EAGAIN;  
        goto exit;
    }

    /* Wait for packets to be available in the queue. */
    ret = wait_event_interruptible(ulan_read_wait_queue, queue_len() != 0);
    if (unlikely(ret)) {
        ret = -EINTR;
        goto exit;
    } 

read:
    ret = -EFAULT;
    skb = dequeue();

    if (likely(skb)) {
        /*
         * Check if user buffer is smaller than the packet size and 
         * return packet back to queue.
         */
        if (count < skb->len) {
            push(skb);  
            ret = -EINVAL;
            goto exit;
        }

        /* 
         * Copy packet data to user buffer.
         * Return packet back to queue in case of copy error.
         */
        if (copy_to_user(buf, skb->data, skb->len)) {
            push(skb);  
            ret = -EFAULT;
            goto exit;
        }

        /* 
         * Return number of bytes read and Free the skb after reading.
         */
        ret = skb->len;
        dev_kfree_skb(skb);  
    }
exit:
    return ret;
}

static int ulan_io_open(struct inode *inode, struct file *file) {
    // Check if device is already open
    if (atomic_cmpxchg(&device_open, FALSE, TRUE)) {
        return -EBUSY;
    }

    // ToDo: Verificar si el device fue abierto como lectura/escritura
    // (filp->f_flags & O_ACCMODE) == O_RDWR

    ulan_change_carrier(dev_ulan, CARRIER_ON);

    return nonseekable_open(inode, file);
}

static int ulan_io_close(struct inode *inode, struct file *filp) {

    atomic_set(&device_open, FALSE);
    ulan_change_carrier(dev_ulan, CARRIER_OFF);
    clean_xmit_queue();
    return 0;
}


static struct file_operations ulan_fops = {
    .read    = ulan_io_read,
    .write   = ulan_io_write,
    .open    = ulan_io_open,
    .release = ulan_io_close,
    .llseek  = no_llseek,
};

static struct miscdevice ulan_miscdev = {
    .minor = MISC_DYNAMIC_MINOR,	/* kernel dynamically assigns a free minor# */
    .name  = DEVICE_NAME,	
    .mode  = 0666,		
    .fops  = &ulan_fops,	    	/* connect to this driver's 'functionality' */
};


/*===========================================================================================*
 * Linux Kernel Module ulandrv.ko															 *
 *===========================================================================================*/
static int __init ulan_init(void) {
    int ret;

    ret = misc_register(&ulan_miscdev);
    if (ret) {
        pr_notice("misc device %s registration failed, aborting\n", DEVICE_NAME);
        return ret;
    }

    xmit_queue.xmit_len   = 0;
    mutex_init(&xmit_queue.xmit_mutex);
    __skb_queue_head_init(&xmit_queue.xmit_head);

    pr_info("misc driver (major # 10) registered, minor# = %d,"
        " dev node is /dev/%s\n", ulan_miscdev.minor, ulan_miscdev.name);

    down_write(&pernet_ops_rwsem);
    rtnl_lock();
    ret = __rtnl_link_register(&ulan_link_ops);
    if (ret < 0)
        goto out;

    ret = ulan_init_one();
    
    if (ret < 0)
        __rtnl_link_unregister(&ulan_link_ops);

    pr_info("net device registered, dev node is /dev/%s\n", IFNAME);

out:
    rtnl_unlock();
    up_write(&pernet_ops_rwsem);

    ulan_change_carrier(dev_ulan, CARRIER_OFF);

    return ret;
}

static void __exit ulan_exit(void) {
    misc_deregister(&ulan_miscdev);
    rtnl_link_unregister(&ulan_link_ops);
    pr_info("misc device (/dev/%s) driver and net device (/dev/%s) driver deregistered\n", DEVICE_NAME, IFNAME);
}


MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Emiliano A. Billi");
module_init(ulan_init);
module_exit(ulan_exit);