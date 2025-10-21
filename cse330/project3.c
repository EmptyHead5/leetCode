#include<linux/kthread.h>
#include<linux/spinlock.h>
#include<linux/sched.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include<linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/module.h>

#define EXIT_ZOMBIE   0x00000020

static int prod=1;
static int cons=0;
static int size=1;
static int uid=0;
static struct semaphore empty;
static struct semaphore full;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Producer Consumer Kernel Module");
module_param(prod, int, 0644);
MODULE_PARM_DESC(prod, "number of producer threads");
module_param(cons, int, 0644);
MODULE_PARM_DESC(cons, "number of consumer threads");
module_param(size, int, 0644);
MODULE_PARM_DESC(size, "bounded buffer size");
module_param(uid, int, 0644);
MODULE_PARM_DESC(uid, "test user UID");

struct buffer{
int size;
int head;
int tail;
int count;
struct task_struct **arr;
spinlock_t lock;
};static struct buffer buf;
struct thread_arg
{
    int id;
};
static struct buffer *b=&buf;
static struct task_struct **producers;
static struct task_struct **consumers;
static void buffer_init(struct buffer *r, int n)
{
r->arr = kmalloc_array(n, sizeof(struct task_struct *), GFP_KERNEL); 
r->size=n;
r->head=0;
r->count=0;
r->tail=0;
spin_lock_init(&r->lock);
}






static int producerThread(void *data){
	struct thread_arg *arg=data;
    int id=arg->id;
    kfree(arg);


	while(!kthread_should_stop())
	{
		struct task_struct *p;
		for_each_process(p)
		{
		 if(p->cred->uid.val!=uid)
			continue;
		if(!(p->exit_state & EXIT_ZOMBIE))
			continue;
		pid_t pid=p->pid;
        pid_t ppid;
                if(p->real_parent)
			ppid=p->real_parent->pid;
		else
			ppid=0;
		get_task_struct(p);
		if(down_interruptible(&empty))
		{
		put_task_struct(p);
		if(kthread_should_stop())
		break;
		else
		continue;
		}
		
		
		spin_lock(&b->lock);
		b->arr[b->tail]=p;
		b->tail =(b->tail+1)%b->size;
		b->count++;
		spin_unlock(&b->lock);
		up(&full);
		  printk(KERN_INFO "[Producer-%d] has produced a zombie process with pid %d and parent pid %d\n",id, pid, ppid);

		msleep(100);
		}

	}
    return 0;
}


static int consumerThread(void *data) 
{
    struct thread_arg *arg=data;
    int id=arg->id;
    kfree(arg);
    while(!kthread_should_stop())
    {
        struct task_struct *p;
        if(down_interruptible(&full))
        {
        if(kthread_should_stop())
        break;
        else
        continue;
        }
        
        spin_lock(&b->lock);
        p=b->arr[b->head];
        b->head=(b->head+1)%b->size;
        b->count--;
        spin_unlock(&b->lock);
        up(&empty);
        
        if(p)
        {
            pid_t pid=p->pid;
            pid_t ppid;
            if(p->real_parent)
                ppid=p->real_parent->pid;
            else
                ppid=0;
            put_task_struct(p);
            printk(KERN_INFO "[Consumer-%d] has consumed a zombie process with pid %d and parent pid %d\n",id, pid, ppid);
            msleep(150);
        }
        
    }
    return 0;
}

static int __init pc_init(void)
{
    
    buffer_init(&buf,size);
    sema_init(&empty,size);
    sema_init(&full,0);
    if(prod<1 || cons<1 || size<1 || uid<0)
    {
        return -1;
    }

    producers=kmalloc_array(prod, sizeof(struct task_struct *), GFP_KERNEL);
    consumers=kmalloc_array(cons, sizeof(struct task_struct *), GFP_KERNEL);
    int i;
    for(i=0;i<prod;i++)
    {
        struct thread_arg *arg=kmalloc(sizeof(struct thread_arg), GFP_KERNEL);
        arg->id=i;
        producers[i]=kthread_run(producerThread, arg, "producer-%d", i);
    }
    for(i=0;i<cons;i++)
    {
        struct thread_arg *arg=kmalloc(sizeof(struct thread_arg), GFP_KERNEL);
        arg->id=i;
        consumers[i]=kthread_run(consumerThread, arg, "consumer-%d", i);
    }
    return 0;
}
static void __exit pc_exit(void)
{
    int i;
    if(producers)
    {
        for(i=0;i<prod;i++)
        {
            if(producers[i])
            {
                kthread_stop(producers[i]);
            }
        }
         kfree(producers);
    }
    if(consumers)
    {
        for(i=0;i<cons;i++) 
        {
            if(consumers[i])
            {
                kthread_stop(consumers[i]);
            }
        }
        kfree(consumers);
    }
    kfree(buf.arr);
    printk(KERN_INFO "Module exited\n");
}

module_init(pc_init);
module_exit(pc_exit);
