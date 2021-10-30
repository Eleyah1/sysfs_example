#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eleyah Melamed");

static unsigned int dropFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int acceptFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
ssize_t getDroppedPacketsData(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t getAcceptedPacketsData(struct device *dev, struct device_attribute *attr, char *buf);
ssize_t resetData(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

static int major_number;
static struct class* myClass = NULL;
static struct device* packetsResetDevice = NULL;
static struct device* packetsDroppedDevice = NULL;
static struct device* packetsAcceptedDevice = NULL;
static unsigned int acceptedPackets = 0;
static unsigned int droppedPackets = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static struct nf_hook_ops nfhoDrop = {
	.hook 	= (nf_hookfn*)dropFunc,		 /* hook function */
	.hooknum 	= NF_INET_FORWARD,		/* packets destined to pass to another interface */
	.pf 	= PF_INET,			/* IPv4 */
	.priority 	= NF_IP_PRI_FIRST,		/* max hook priority */
};
static struct nf_hook_ops nfhoAcceptInput = {
	.hook 	= (nf_hookfn*)acceptFunc,		/* hook function */
	.hooknum 	= NF_INET_LOCAL_IN,		/* packets destined to the FW */
	.pf 	= PF_INET,			/* IPv4 */
	.priority 	= NF_IP_PRI_FIRST,		/* max hook priority */
};
static struct nf_hook_ops nfhoAcceptOutput = {
	.hook 	= (nf_hookfn*)acceptFunc,		/* hook function */
	.hooknum 	= NF_INET_LOCAL_OUT,		/* packets from the FW */
	.pf 	= PF_INET,			/* IPv4 */
	.priority 	= NF_IP_PRI_FIRST,		/* max hook priority */
};


ssize_t getAcceptedPacketsData(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", acceptedPackets);
}

ssize_t getDroppedPacketsData(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", droppedPackets);
}

ssize_t resetData(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	acceptedPackets = 0;
	droppedPackets = 0;
	return count;	
}

//creates struct device_attribute_dropped_packets
static DEVICE_ATTR(dropped_packets,  S_IWUSR | S_IRUGO, getDroppedPacketsData, NULL);

//creates struct device_attribute_accepted_packets 
static DEVICE_ATTR(accepted_packets, S_IWUSR | S_IRUGO, getAcceptedPacketsData, NULL);

//creates struct device_attribute_reset_packets 
static DEVICE_ATTR(reset_packets, S_IWUSR | S_IRUGO, NULL, resetData);

/*
We drop every packet that's not intended for the FW
in order to block connection going through it.
That way we allow only local connection to/from the FW.
*/
static unsigned int dropFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	printk("*** Packet Dropped ***");
	droppedPackets++;
	return NF_DROP;
}

/*
We accept every packet that's intended to/from the FW.
That way we allow connection to/from the FW.
*/
static unsigned int acceptFunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	printk("*** Packet Accepted ***");
	acceptedPackets++;
	return NF_ACCEPT;
}

int init_module(){
	//create first hook
	if (nf_register_net_hook(&init_net, &nfhoDrop))
	{
		return -1;	
	}

	//create second hook
	if (nf_register_net_hook(&init_net, &nfhoAcceptInput))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		return -1;
	}
	
	//create third hook
	if(nf_register_net_hook(&init_net, &nfhoAcceptOutput))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		return -1;
	}

	//create char device
	major_number = register_chrdev(0, "Sysfs_Device", &fops);\
	if (major_number < 0)
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		return -1;
	}
		
	//create sysfs class
	myClass = class_create(THIS_MODULE, "myClass");
	if (IS_ERR(myClass))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs device for reading the number of accepted packets
	packetsAcceptedDevice = device_create(myClass, NULL, MKDEV(major_number, 0), NULL, "packetsAcceptedDevice");	
	if (IS_ERR(packetsAcceptedDevice))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes for reading the number of accepted packets	
	if (device_create_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		device_destroy(myClass, MKDEV(major_number, 0));
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	//create sysfs device for reading the number of dropped packets
	packetsDroppedDevice = device_create(myClass, NULL, MKDEV(major_number, 1), NULL, "packetsDroppedDevice");	
	if (IS_ERR(packetsDroppedDevice))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		device_remove_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
		device_destroy(myClass, MKDEV(major_number, 0));
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes for reading the number of dropped packets	
	if (device_create_file(packetsDroppedDevice, (const struct device_attribute *)&dev_attr_dropped_packets.attr))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		device_remove_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
		device_destroy(myClass, MKDEV(major_number, 0));
		device_destroy(myClass, MKDEV(major_number, 1));
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	//create sysfs device for reseting the number of packets
	packetsResetDevice = device_create(myClass, NULL, MKDEV(major_number, 2), NULL, "packetsResetDevice");	
	if (IS_ERR(packetsResetDevice))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		device_remove_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
		device_remove_file(packetsDroppedDevice, (const struct device_attribute *)&dev_attr_dropped_packets.attr);
		device_destroy(myClass, MKDEV(major_number, 0));
		device_destroy(myClass, MKDEV(major_number, 1));
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}
	
	//create sysfs file attributes for reseting the number of packets	
	if (device_create_file(packetsResetDevice, (const struct device_attribute *)&dev_attr_reset_packets.attr))
	{
		nf_unregister_net_hook(&init_net, &nfhoDrop);
		nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
		nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
		device_remove_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
		device_remove_file(packetsDroppedDevice, (const struct device_attribute *)&dev_attr_dropped_packets.attr);
		device_destroy(myClass, MKDEV(major_number, 0));
		device_destroy(myClass, MKDEV(major_number, 1));
		device_destroy(myClass, MKDEV(major_number, 2));
		class_destroy(myClass);
		unregister_chrdev(major_number, "Sysfs_Device");
		return -1;
	}

	return 0; /* return 0 is success */
}

void cleanup_module(){
	nf_unregister_net_hook(&init_net, &nfhoDrop);
	nf_unregister_net_hook(&init_net, &nfhoAcceptInput);
	nf_unregister_net_hook(&init_net, &nfhoAcceptOutput);
	device_remove_file(packetsAcceptedDevice, (const struct device_attribute *)&dev_attr_accepted_packets.attr);
	device_remove_file(packetsDroppedDevice, (const struct device_attribute *)&dev_attr_dropped_packets.attr);
	device_remove_file(packetsResetDevice, (const struct device_attribute *)&dev_attr_reset_packets.attr);
	device_destroy(myClass, MKDEV(major_number, 0));
	device_destroy(myClass, MKDEV(major_number, 1));
	device_destroy(myClass, MKDEV(major_number, 2));
	class_destroy(myClass);
	unregister_chrdev(major_number, "Sysfs_Device");
}
