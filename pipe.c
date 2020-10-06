#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/atomic.h>
#include <asm/uaccess.h>
#include "blowfish.h"


#define MODULE_NAME "CryptoPipe"
#define FIRST_DEVICE 0
#define DEVICE_COUNT 4
#define BLOCKS_IN_BUFFER 10000
//////////////////////////////////////////////////////
static int open_function(struct inode *inode, struct file *filp);
static int release_function(struct inode *inode, struct file *filp);
static ssize_t read_function(struct file *filp, char __user *buf, size_t count, loff_t *offp);
static ssize_t write_fuction(struct file *filp, const char __user *buff, size_t count, loff_t *offp);

//////////////////////////////////////////////////////
enum PROCESSING_TYPE
{
    TYPE_ENCRYPTION,
    TYPE_DECRYPTION
};

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_function,
    .write = write_fuction,
    .open = open_function,
    .release = release_function,
    .llseek = NULL
    }; 

static unsigned int major = 0;
static unsigned int type_param[DEVICE_COUNT];
static char *key_param[DEVICE_COUNT];

module_param(major, uint, 0);
module_param_array(type_param, int, NULL, 0);
module_param_array(key_param, charp, NULL, 0);

///////////////////////////////////////////////////////


struct crypto_block
{
    wait_queue_head_t read_queue, write_queue;    
    char *buffer, *end;
    char *wp, *rp;
    int buffer_size;
    atomic_t reader, writer;  
    int block_size;
    size_t total_written;
    int at_exit;
    void (*process_block)(struct BLOWFISH_CTX*, unsigned int*, unsigned int*);
    struct BLOWFISH_CTX *ctx;
    struct semaphore sem;
    struct cdev dev;    
   
};
static struct crypto_block* cr_blocks[DEVICE_COUNT];

//setup and delete functions
/////////////////////////////////////////////

static int setup_crypto_block(struct crypto_block *block, int index, enum PROCESSING_TYPE type, unsigned char *key)
{
    dev_t dev_num = MKDEV(major, FIRST_DEVICE + index);

    cdev_init(&block->dev, &fops);
    block->dev.owner = THIS_MODULE;
    block->dev.ops = &fops;

    init_waitqueue_head(&block->read_queue);
    init_waitqueue_head(&block->write_queue);

    block->block_size = 8;
    block->total_written = 0;
    block->at_exit = 0;

    if(!(block->buffer = kmalloc(block->block_size * BLOCKS_IN_BUFFER, GFP_KERNEL)))
    {
        printk(KERN_ERR "CryptoPipe: error allocating memory to device %d buffer\n", index);
        return -ENOMEM;
    }

    block->end = block->buffer + block->block_size * BLOCKS_IN_BUFFER;
    block->buffer_size = block->block_size * BLOCKS_IN_BUFFER;

    block->rp = block->buffer;
    block->wp = block->buffer;

    atomic_set(&block->writer, 0);
    atomic_set(&block->reader, 0);  
      
    if(type == TYPE_ENCRYPTION)
        block->process_block = blowfish_encrypt_block;
    else
        block->process_block = blowfish_decrypt_block;

    if(!(block->ctx = kmalloc(sizeof(struct BLOWFISH_CTX), GFP_KERNEL)))
    {
        printk(KERN_ERR "CryptoPipe: error allocating memory to device's %d ctx\n", index);
        return -ENOMEM;   
    }
    blowfish_init(block->ctx, key, strlen(key)); 
    
    sema_init(&block->sem, 1);

    if(cdev_add(&block->dev, dev_num, 1))
    {
        printk(KERN_ERR "CryptoPipe: cannot add a crypto block device %d\n", index);
        return -ENOMEM;
    }
    printk(KERN_INFO "CryptoPipe: device successfully registered (major %d , minor %d)\n", MAJOR(dev_num), MINOR(dev_num));
    return 0;
}

static void delete_crypto_block(struct crypto_block *block)
{
    dev_t dev_num = block->dev.dev;
    if(block->buffer != NULL)
        kfree(block->buffer);
    if(block->ctx != NULL)
        kfree(block->ctx);
    cdev_del(&block->dev);

    if(block != NULL)
        kfree(block);
    block = NULL;
    printk(KERN_INFO "CryptoPipe: device deleted (major%d , minor %d)\n", MAJOR(dev_num), MINOR(dev_num));   
}
//init and exit functions
/////////////////////////////////////////////////////////////////////////////
static int __init init_function(void)
{
    dev_t dev_num;  //переменная хранения номера устройства
    int ret;        //возращаемое значение для контроля ошибок
    int i; 

    if(major)
    {
        dev_num = MKDEV(major, FIRST_DEVICE);
        ret = register_chrdev_region(dev_num, DEVICE_COUNT, MODULE_NAME); 
    }
    else
    {
        ret = alloc_chrdev_region(&dev_num, FIRST_DEVICE, DEVICE_COUNT, MODULE_NAME);
        major = MAJOR(dev_num); 
    }
    if(ret < 0)
    {
        printk(KERN_ERR "CryptoPipe: can't register device region with %d major number\n", major);
        goto error;
    }

    for(i = 0; i < DEVICE_COUNT; i++)
    {
        if(!(cr_blocks[i] = kmalloc(sizeof(struct crypto_block), GFP_KERNEL)))
        {   
            printk(KERN_ERR "CryptoPipe: error allocating memory to crypto block %d\n", i);
            goto error;
        }       
        memset(cr_blocks[i], 0, sizeof(struct crypto_block));
        
     /*   if(type_param[i] != 0 || type_param[i] != 1)
        {
            printk(KERN_ERR "CryptoPipe: wrong processing type parameter: %d\n", type_param[i]);
            goto error;
        }*/
            
        setup_crypto_block(cr_blocks[i], i, (enum PROCESSING_TYPE)type_param[i], (unsigned char*)key_param[i]);            
    }
        
    printk(KERN_INFO "CryptoPipe: module successfully installed (major %d , minor %d)\n", MAJOR(dev_num), MINOR(dev_num));

    return 0;

    error:
        
        return ret;

}

static void __exit exit_function(void)
{
    int i;
    dev_t dev_num = MKDEV(major, FIRST_DEVICE);
    unregister_chrdev_region(dev_num, DEVICE_COUNT);
    
    for(i = 0; i < DEVICE_COUNT; i++)
        delete_crypto_block(cr_blocks[i]);

    printk(KERN_INFO "CryptoPipe: module successfully removed (major%d , minor %d)\n", MAJOR(dev_num), MINOR(dev_num)); 
}
///////////////////////////////////////////////////////////////////////////////////////

static int open_function(struct inode *inode, struct file *filp)
{
    struct crypto_block *block = container_of(inode->i_cdev, struct crypto_block, dev);
    
    if(filp->f_mode == (FMODE_READ | FMODE_WRITE))
    {
        return -EACCES;
    }

    if(filp->f_mode & FMODE_READ)
    {    
        if(atomic_dec_and_test(&block->reader))
        {
            atomic_inc(&block->reader);
            return -EBUSY;
        }        
        atomic_set(&block->reader, 1);
    }
    if(filp->f_mode & FMODE_WRITE)
    {   
        if(atomic_dec_and_test(&block->writer))
        {
            atomic_inc(&block->writer);
            return -EBUSY;
        }        
        atomic_set(&block->writer,1);    
    }
    filp->private_data = block;
    return 0;
}

static inline void reset_crypto_block(struct crypto_block *block)
{
    block->rp = block->buffer;
    block->wp = block->buffer;   
}

static int release_function(struct inode *inode, struct file *filp)
{
    struct crypto_block *block = container_of(inode->i_cdev, struct crypto_block, dev);

    if(filp->f_mode & FMODE_READ)
    {
        if(!atomic_read(&block->writer))
            reset_crypto_block(block);
            block->at_exit = 0;        
        atomic_set(&block->reader, 0);
    }

    if(filp->f_mode & FMODE_WRITE)
    {
        if(!atomic_read(&block->reader))
            reset_crypto_block(block);
            block->at_exit = 1;
            wake_up_interruptible(&block->read_queue);
        atomic_set(&block->writer, 0); 
    }   
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////
static void process_array(struct crypto_block *block, unsigned char* arr, int len)
{
    int i;
    unsigned int l = 0, r = 0;
    
    for(i = 0; i < len; i += 8)
    {
        l = arr[i];
        l = (l << 8) | arr[i + 1];
        l = (l << 8) | arr[i + 2];
        l = (l << 8) | arr[i + 3];

        r = arr[i + 4];
        r = (r << 8) | arr[i + 5];
        r = (r << 8) | arr[i + 6];
        r = (r << 8) | arr[i + 7];
        
        block->process_block(block->ctx, &l, &r);

        arr[i] = (l >> 24) & 0xff;
        arr[i + 1] = (l >> 16) & 0xff;
        arr[i + 2] = (l >> 8) & 0xff;
        arr[i + 3] = l & 0xff;

        arr[i + 4] = (r >> 24) & 0xff;
        arr[i + 5] = (r >> 16) & 0xff;
        arr[i + 6] = (r >> 8) & 0xff;
        arr[i + 7] = r & 0xff;
    }
}


static int space_for_reading(struct crypto_block *block)
{
    if(block->rp == block->wp)
        return 0;
    return ((block->wp + block->buffer_size - block->rp) % block->buffer_size) - 1;
}

static ssize_t read_function(struct file *filp, char __user *buf, size_t count, loff_t *offp)
{
    struct crypto_block *block = filp->private_data;

    if((space_for_reading(block) < block->block_size -1))
    {
        printk(KERN_DEBUG "process %s(%d) reading: going to sleep, space %d\n", current->comm, current->pid, space_for_reading(block));
        if(wait_event_interruptible(block->read_queue, ( (space_for_reading(block) >= block->block_size -1) || block->at_exit ) ) )  
            return -ERESTARTSYS;
        printk(KERN_DEBUG "process %s(%d) reading: wake up!!!\n", current->comm, current->pid);
    }    
    if(block->wp == block->rp)
        return 0;
    if(block->wp > block->rp)
        count = min(count, (size_t)(block->wp - block->rp));
    else
        count = min(count, (size_t)(block->end - block->rp));

    count = (count / block->block_size) * block->block_size;
    
    process_array(block, block->rp, count);

    if(raw_copy_to_user(buf, block->rp, count))
        return -EFAULT;
   
    block->rp += count;
    if(block->rp == block->end)
        block->rp = block->buffer;
    
    wake_up_interruptible(&block->write_queue);

    printk(KERN_DEBUG "\"%s\" did read %li bytes\n",current->comm, (long)count);
    return count;
}

static int space_for_writing(struct crypto_block *block)
{
    if(block->rp == block->wp)
        return block->buffer_size - 1;
    return ((block->rp + block->buffer_size - block->wp) % block->buffer_size) - 1;
}

static ssize_t write_fuction(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{
    struct crypto_block *block = filp->private_data;

    if(space_for_writing(block) == 0)
    {
        printk(KERN_DEBUG "process %s(%d) writing: going to sleep\n", current->comm, current->pid);
        if(wait_event_interruptible(block->write_queue, (space_for_writing(block) != 0)))
            return -ERESTARTSYS;
        printk(KERN_DEBUG "process %s(%d) writing: wake up!!!\n", current->comm, current->pid);

    }

    count = min(count, (size_t)space_for_writing(block));
    if(block->wp >= block->rp)
        count = min(count, (size_t)(block->end - block->wp));
    else
        count = min(count, (size_t)(block->rp - block->wp - 1));
    printk(KERN_DEBUG "Going to accept %li bytes to %p from %p\n", (long)count, block->wp, buf);

    if(raw_copy_from_user(block->wp, buf, count))
        return -EFAULT;

    block->wp += count;
    if(block->wp == block->end)
        block->wp = block->buffer;

    wake_up_interruptible(&block->read_queue);
    printk(KERN_DEBUG "\"%s\" did write %li bytes\n",current->comm, (long)count);
    return count;
}

///////////////////////////////////////////////////////////////////////////
module_init(init_function);
module_exit(exit_function);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mihail Mihalchenko");
MODULE_DESCRIPTION("Provides the channel with a symmetric-key block encryption and decryption");
////////////////////////////////////////////////////////////////////////////////////////////////////

