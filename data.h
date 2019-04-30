#include<linux/types.h>
#include<linux/sched.h>
#include<linux/string.h>
#include <linux/writeback.h>
#include<linux/freezer.h>
#include<linux/list_sort.h>
#define BIO_THREHOLD 1000
static struct kmem_cache *latent_cache,*wb_cache;
static struct list_head alloc_list;
struct mutex alloc_lock;

static int latent_alloc_thread_func(void *data);
static int __write_data_page(struct page *page, bool *submitted,
				struct writeback_control *wbc,
				enum iostat_type io_type);
int free_latent_list(struct list_head *head);
                
int compare(void *priv, struct list_head *a, struct list_head *b);
/*
struct __wait_queue_head {
	spinlock_t lock;
	struct list_head task_list;
};
*/
struct latent_alloc{
	int ino;
	struct address_space *mapping;
	struct page *page; //会不会被free?
	struct writeback_control *wbc;
    int flushed;
    int io_type;
	struct list_head next;
};
struct f2fs_latent_alloc_kthread{
    int wake;//一般情况默认为0，wake=1一般是系统恢复时强制使用
    int last_latency;
    int sleep_time;
    struct task_struct *thread;
    wait_queue_head_t  alloc_wait_queue_head;

};
struct list_head cache_alloc_head;
int hasflush=0,wait_flush=0;

int __init init_latent_alloc_caches(void){
    INIT_LIST_HEAD(&cache_alloc_head);
    mutex_init(&alloc_lock);
    latent_cache=f2fs_kmem_cache_create("latent_alloc_slab",
										 sizeof(struct latent_alloc));
    if(!latent_cache) goto destroy_latent;
    wb_cache=f2fs_kmem_cache_create("writeback_alloc_slab",
										 sizeof(struct writeback_control));
    if(!wb_cache) goto destroy_WB;
    return 0;
destroy_WB:
	kmem_cache_destroy(wb_cache);
destroy_latent:
    kmem_cache_destroy(latent_cache);
	latent_cache=wb_cache=NULL;
	printk("NOMEM! latent_cache=%x,wb_cache=%x\n",latent_cache,wb_cache);
	return -ENOMEM;
                                         
}
//should add lock before call flush_urgent()!
int flush_urgent(void){
    
    struct list_head *pos;
    bool submitted;
    int ret=0,last_idx;
	printk("I'm working? waitflush=%d\n",wait_flush); //排序时卡死

    list_sort(NULL,&cache_alloc_head,compare);//排序，失败？
	printk("sort finish");
    list_for_each(pos, &cache_alloc_head){
        	struct latent_alloc *ie = list_entry(pos, struct latent_alloc, next);
            struct writeback_control *wbc=ie->wbc;
            struct page *page=ie->page;
retry_write2:
            //lock_page(ie->page);
			printk("before write index=%ld\n",page->index);//key
            ret = __write_data_page(ie->page, &submitted, wbc, ie->io_type);
			printk("ret=%d\n",ret);
            printk("flush_urgent: inode=%d ",page->mapping->host->i_ino);
			printk(" index=%ld\n",page->index);//key
			if (unlikely(ret)) {
				if (ret == AOP_WRITEPAGE_ACTIVATE) {
					unlock_page(page);
					ret = 0;
					continue;
				} else if (ret == -EAGAIN) {
					ret = 0;
					if (wbc->sync_mode == WB_SYNC_ALL) {
						cond_resched();
						congestion_wait(BLK_RW_ASYNC,
									HZ/50);
						goto retry_write2;
					}
					continue;
				}
                printk("async write... dangerous\n");
				//done_index = page->index + 1;
				//done = 1;
				break;
			} 
			//static void __page_cache_release(struct page *page)
			//__page_cache_release(page);//释放页
			 //release_pages(struct page **pages, int nr);
			  release_pages(&page, 1);
			/*else if (submitted) {
				last_idx = page->index;
			}*/
            --wbc->nr_to_write;
            ++hasflush;
            --wait_flush;
            ie->flushed=1;
			/* give a priority to WB_SYNC threads */
			/*if ((atomic_read(&F2FS_M_SB(mapping)->wb_sync_req) ||
					--wbc->nr_to_write <= 0) &&
					wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}*/

    }
    free_latent_list(&cache_alloc_head);//扔掉下发成功的IO
}
int add_item(int i_num, struct address_space *map, struct page *page, struct writeback_control *wbc, int io_type){
    	struct latent_alloc *new = f2fs_kmem_cache_alloc(latent_cache,
											   GFP_NOFS);
        new->ino=i_num;
        new->mapping=map;
        new->page=page;
        new->wbc=wbc;
        new->flushed=0;
        new->io_type=io_type;
        list_add_tail(&(new->next),&cache_alloc_head);
}
int free_latent_list(struct list_head *head){
	struct latent_alloc *pos,*temp;
	//struct gc_sort *ie;
	list_for_each_entry_safe(pos, temp, head, next){
		//ie = list_entry(pos, struct gc_sort, ilist);
        if(pos->flushed){
            list_del(&(pos->next));//还需要从链表中移除
		    kmem_cache_free(latent_cache,pos);
        }
		
	}
    
}
int start_latent_alloc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_latent_alloc_kthread *gc_th;
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err = 0;
	gc_th = f2fs_kmalloc(sbi, sizeof(struct f2fs_latent_alloc_kthread), GFP_KERNEL);
	if (!gc_th)
	{
		err = -ENOMEM;
		goto out;
	}
	gc_th->wake = 0;
    gc_th->sleep_time=30*1000;
	sbi->latent_alloc_kthread = gc_th;
	init_waitqueue_head(&sbi->latent_alloc_kthread->alloc_wait_queue_head);
	sbi->latent_alloc_kthread->thread = kthread_run(latent_alloc_thread_func, sbi,
											   "f2fs_lantent_alloc-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(gc_th->thread))
	{
		err = PTR_ERR(gc_th->thread);
		kfree(gc_th);
		sbi->latent_alloc_kthread = NULL;
	}
out:
	return err;
}
static int latent_alloc_thread_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct f2fs_latent_alloc_kthread *gc_th = sbi->latent_alloc_kthread;
	wait_queue_head_t *wq = &sbi->latent_alloc_kthread->alloc_wait_queue_head;
	unsigned int wait_ms;

	wait_ms = gc_th->sleep_time;

	set_freezable();
	do
	{
		wait_event_interruptible_timeout(*wq,
										 kthread_should_stop() || freezing(current) ||
											 gc_th->wake,
										 msecs_to_jiffies(wait_ms));
        printk("latent_alloc_thread_func wakes up,wake=%d\n",gc_th->wake);
		if (gc_th->wake)
			gc_th->wake = 0;

		if (try_to_freeze())
			continue;
		if (kthread_should_stop())
			break;
		/*if (!sb_start_write_trylock(sbi->sb))
			continue;*/
		/* if return value is not zero, no victim was selected */
		//if (f2fs_gc(sbi, test_opt(sbi, FORCE_FG_GC), true, NULL_SEGNO))//块的数目过少
        mutex_lock(&alloc_lock);
        if(wait_flush==0) {
			mutex_unlock(&alloc_lock);//忘记解锁！
			continue;
		}
        if(gc_th->last_latency==0){
            if(wait_flush>BIO_THREHOLD){//flush
                printk("flush begins in thread\n");
                flush_urgent();
            }
            else gc_th->last_latency=1;//can add wake time
            mutex_unlock(&alloc_lock);
            continue;
        }
        if(gc_th->last_latency>0){//flush
            gc_th->last_latency--;
            flush_urgent();
        }
       //强制刷写
       //gc_th->sleep_time =(wait_ms+10)>60?60:(wait_ms+10);
        mutex_unlock(&alloc_lock);

	} while (!kthread_should_stop());
	return 0;
}

void stop_latent_alloc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_latent_alloc_kthread *alloc_th = sbi->latent_alloc_kthread;
	if (!alloc_th)
		return;
    flush_urgent();
	kthread_stop(alloc_th->thread);
	kfree(alloc_th);
	sbi->latent_alloc_kthread = NULL;
}

//release slab
void destroy_latent_alloc_caches(void)
{
	if(latent_cache)
	kmem_cache_destroy(latent_cache);
    if(wb_cache)
    kmem_cache_destroy(wb_cache);
}
int compare(void *priv, struct list_head *a, struct list_head *b){
    struct address_space *tempa,*tempb;
    int indexofA,indexofB;
    int inodeA,inodeB;
    if(a&&b){
        tempa=list_entry(a,struct latent_alloc, next)->mapping;
        tempb=list_entry(b,struct latent_alloc, next)->mapping;
        if(list_entry(a,struct latent_alloc, next)->page->mapping != tempa || list_entry(b,struct latent_alloc, next)->page->mapping != tempb){
            printk("error！mapping inconsistent\n");
            return 0;
        }
        if(tempa && tempb){
            inodeA=tempa->host->i_ino;
            inodeB=tempb->host->i_ino;
        }
        indexofA=(list_entry(a,struct latent_alloc, next)->page)->index;
        indexofB=(list_entry(b,struct latent_alloc, next))->page->index;
        if(inodeA<inodeB){
            return -1; 
        }
        else if(inodeA==inodeB){
            return indexofA<indexofB;
        }
        else
            return 1;
    }
    return 0;

}
