#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/writeback.h>
#include <linux/freezer.h>
#include <linux/list_sort.h>

#define BIO_THREHOLD 400 //一个脏inode最多存48？

static int f2fs_write_data_page(struct page *page,
								struct writeback_control *wbc);
//缓冲位置
static struct kmem_cache *latent_cache, *wb_cache;
//static struct list_head alloc_list;

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
struct latent_alloc
{
	int ino;
	struct address_space *mapping;
	struct page *page; //会不会被free?
	//struct writeback_control wbc;
	struct
	{
		long nr_to_write;   /* Write this many pages, and decrement					   this for each page written */
		long pages_skipped; /* Pages which were not written */
		/*
	 * For a_ops->writepages(): if start or end are non-zero then this is
	 * a hint that the filesystem need only write out the pages inside that
	 * byterange.  The byte at `end' is included in the writeout request.
	 */
		loff_t range_start;
		loff_t range_end;
		enum writeback_sync_modes sync_mode;
		unsigned for_kupdate : 1;		/* A kupdate writeback */
		unsigned for_background : 1;	/* A background writeback */
		unsigned tagged_writepages : 1; /* tag-and-write to avoid livelock */
		unsigned for_reclaim : 1;		/* Invoked from the page allocator */
		unsigned range_cyclic : 1;		/* range_start is cyclic */
	} wbc;
	int flushed;
	int io_type;
	struct list_head next;
};
struct f2fs_latent_alloc_kthread
{
	int wake; //一般情况默认为0，wake=1一般是系统恢复时强制使用
	int last_latency;
	int sleep_time;
	struct task_struct *thread;
	wait_queue_head_t alloc_wait_queue_head;
};
/*
struct list_head cache_alloc_head;
struct inode *rencently_inode;
struct mutex alloc_lock;
int hasflush=0,wait_flush=0;*/

int __init init_latent_alloc_caches(void)
{
	/*INIT_LIST_HEAD(&cache_alloc_head);
	 mutex_destroy(&alloc_lock);
    mutex_init(&alloc_lock);*/

	latent_cache = f2fs_kmem_cache_create("latent_alloc_slab",
										  sizeof(struct latent_alloc));
	if (!latent_cache)
		goto destroy_latent;
	wb_cache = f2fs_kmem_cache_create("writeback_alloc_slab",
									  sizeof(struct writeback_control));
	printk("size of latent_alloc=%dB,writeback_control=%d", sizeof(struct latent_alloc), sizeof(struct writeback_control));
	if (!wb_cache)
		goto destroy_WB;
	return 0;
destroy_WB:
	kmem_cache_destroy(wb_cache);
destroy_latent:
	kmem_cache_destroy(latent_cache);
	latent_cache = wb_cache = NULL;
	printk("NOMEM! latent_cache=%x,wb_cache=%x\n", latent_cache, wb_cache);
	return -ENOMEM;
}
//should add lock before call flush_urgent()!
//#define pgoff_t unsigned long
int flush_urgent(struct f2fs_sb_info *sbi)
{

	struct list_head *pos;
	bool submitted;
	int ret = 0, last_idx;
	int nr_pages, i;
	pgoff_t index = 0, end;
	struct pagevec pvec;
	struct inode *vfs_inode;
	int flushcount = 0;
	printk("flush_urgent working! waitflush=%d\n", sbi->wait_flush); //排序时卡死
	list_sort(NULL, &sbi->cache_alloc_head, compare);				 //排序
	printk("sort finish... writeback is doing");
	struct blk_plug plug;
	int last_inode = -1, cur_inode;
	struct latent_alloc *ie;

	list_for_each(pos, &sbi->cache_alloc_head)
	{
		ie = list_entry(pos, struct latent_alloc, next);
		struct writeback_control *wbc = (struct writeback_control *)&(ie->wbc);
		struct page *page = ie->page;
		pagevec_init(&pvec);
		end = (ie->mapping->host->i_size + 4093) >> 12;
		index = page->index;
		cur_inode = ie->mapping->host->i_ino;
		if (last_inode != cur_inode)
		{
			printk("before write: inode=%ld, index=%ld, page addr=%x, wbc_start=%d, wbc_end=%d\n",
				   ie->mapping->host->i_ino, page->index, page, wbc->range_start >> 12, wbc->range_end >> 12); //key
			//vfs_inode=f2fs_iget(rencently_inode->i_sb, page->mapping->host->i_ino);
		}
		else
			continue;
		blk_start_plug(&plug);
		while (index < end)
		{
			nr_pages = pagevec_lookup_range_tag(&pvec, ie->mapping, &index, (ie->mapping->host->i_size + 4093) >> 12,
												PAGECACHE_TAG_TOWRITE); //radix tree组织起来，找到slot数组*/
			if (!nr_pages)
				continue;
			for (i = 0; i < nr_pages; i++)
			{
			retry_write2:
				page = pvec.pages[i];
				printk("writing :inode=%d, page's index=%d\n",
					   page->mapping->host->i_ino, page->index); //key
				lock_page(pvec.pages[i]);
				// ret = __write_data_page(ie->page, &submitted, wbc, ie->io_type);
				ret = f2fs_write_data_page(page, wbc);

				if (ret)
					printk("WRANING WRITE FAILURE!! ret=%d,  inode=%d, index=%d", ret, page->mapping->host->i_ino, page->index);
				else
					printk("successfully write");
				if (unlikely(ret))
				{
					if (ret == AOP_WRITEPAGE_ACTIVATE)
					{
						unlock_page(page);
						ret = 0;
						continue;
					}
					else if (ret == -EAGAIN)
					{
						ret = 0;
						if (wbc->sync_mode == WB_SYNC_ALL)
						{
							cond_resched();
							congestion_wait(BLK_RW_ASYNC,
											HZ / 50);
							goto retry_write2; //这种情况的确可能发生，一开始时。。
						}
						continue;
					}
					printk("async write... dangerous\n");
					//done_index = page->index + 1;
					//done = 1;
					break;
				}
				last_idx = page->index;
				wbc->nr_to_write = 0;
				++sbi->hasflush;
				++flushcount;
				--sbi->wait_flush;
				ie->flushed = 1;
				inode_dec_dirty_pages(page->mapping->host);
				//when call sync in shell
				/*
		if (wbc->range_cyclic || (range_whole && nr_write> 0))
			page->mapping->writeback_index = page->index; */
				//static void __page_cache_release(struct page *page)
				//__page_cache_release(page);//释放页
				//release_pages(struct page **pages, int nr);

				// release_pages(&page, 1); //已经有 pagevec_release
				/*else if (submitted) {
				last_idx = page->index;
			}*/
			}
			pagevec_release(&pvec);
		}
		if (flushcount != 0)
		{
			f2fs_submit_merged_write_cond(F2FS_M_SB(ie->mapping), ie->mapping->host,
									  0, last_idx, DATA);
			blk_finish_plug(&plug);
			cond_resched();
		}
		
		remove_dirty_inode(ie->mapping->host);
		last_inode = cur_inode;
		/*
		//太多IO了，直接卡死？
		if (last_idx != ULONG_MAX)
			f2fs_submit_merged_write_cond(F2FS_M_SB(ie->mapping), ie->mapping->host,
						0, last_idx, DATA);*/
		/* give a priority to WB_SYNC threads */
		/*if ((atomic_read(&F2FS_M_SB(mapping)->wb_sync_req) || --wbc->nr_to_write <= 0) && wbc->sync_mode == WB_SYNC_NONE) {
				done = 1;
				break;
			}*/
	}
	
	printk("free_latent_list is freeing useless things");
	free_latent_list(&sbi->cache_alloc_head); //扔掉下发成功的IO
	return 0;
}
int add_item(struct f2fs_sb_info *sbi, int i_num, struct address_space *map, struct page *page, struct writeback_control *wbc, int io_type)
{
	struct latent_alloc *new = f2fs_kmem_cache_alloc(latent_cache,
													 GFP_NOFS);
	new->ino = i_num;
	new->mapping = map;
	new->page = page;
	//new->wbc=wbc;
	new->wbc.range_start = wbc->range_start;
	new->wbc.range_end = wbc->range_end;
	new->wbc.sync_mode = wbc->sync_mode;
	new->wbc.tagged_writepages = wbc->tagged_writepages;
	new->wbc.range_cyclic = wbc->range_cyclic;
	new->flushed = 0;
	new->io_type = io_type;
	list_add_tail(&(new->next), &sbi->cache_alloc_head);
}
int free_latent_list(struct list_head *head)
{
	struct latent_alloc *pos, *temp;
	//struct gc_sort *ie;
	list_for_each_entry_safe(pos, temp, head, next)
	{
		//ie = list_entry(pos, struct gc_sort, ilist);
		if (pos->flushed)
		{
			list_del(&(pos->next)); //还需要从链表中移除
			kmem_cache_free(latent_cache, pos);
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
	gc_th->sleep_time = 30 * 1000;
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
		printk("latent_alloc_thread_func wakes up,sbi->wait=%d\n", sbi->wait_flush);
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
		//if(!mutex_trylock(&sbi->alloc_lock)) contnue;//得不到锁

		mutex_lock(&sbi->alloc_lock);
		if (sbi->wait_flush == 0)
		{
			;
			//mutex_unlock(&sbi->alloc_lock);//忘记解锁！
		}
		else if (sbi->wait_flush > BIO_THREHOLD * 3 / 4)
		{ //reach a threhold,flush it.
			printk("flush triggers for capacity\n");
			flush_urgent(sbi);
			//mutex_unlock(&sbi->alloc_lock);
		}
		else if (gc_th->last_latency == 0)
		{
			gc_th->last_latency = 1; //can add wake time
			//mutex_unlock(&sbi->alloc_lock);
		}
		else if (gc_th->last_latency > 0)
		{ //flush
			gc_th->last_latency--;
			printk("flush triggers for timeout\n");
			flush_urgent(sbi); //TODO...
		}
		//gc_th->sleep_time =(wait_ms+10)>60?60:(wait_ms+10);
		mutex_unlock(&sbi->alloc_lock);
	} while (!kthread_should_stop());
	flush_urgent(sbi);						  //做最后的努力，flush into device
	free_latent_list(&sbi->cache_alloc_head); //扔掉未写入的IO
	mutex_destroy(&sbi->alloc_lock);
	return 0;
}

void stop_latent_alloc_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_latent_alloc_kthread *alloc_th = sbi->latent_alloc_kthread;
	if (!alloc_th)
		return;
	//flush_urgent(); //TODO
	kthread_stop(alloc_th->thread);
	kfree(alloc_th);
	sbi->latent_alloc_kthread = NULL;
}

//release slab
void destroy_latent_alloc_caches(void)
{
	if (wb_cache)
		kmem_cache_destroy(wb_cache);
	if (latent_cache)
		kmem_cache_destroy(latent_cache);
}
int compare(void *priv, struct list_head *a, struct list_head *b)
{
	struct address_space *tempa, *tempb;
	int indexofA, indexofB;
	int inodeA, inodeB;
	if (a && b)
	{
		tempa = list_entry(a, struct latent_alloc, next)->mapping;
		tempb = list_entry(b, struct latent_alloc, next)->mapping;
		if (list_entry(a, struct latent_alloc, next)->page->mapping != tempa || list_entry(b, struct latent_alloc, next)->page->mapping != tempb)
		{
			printk("error！mapping inconsistent\n");
			return 0;
		}
		if (tempa && tempb)
		{
			inodeA = tempa->host->i_ino;
			inodeB = tempb->host->i_ino;
		}
		indexofA = (list_entry(a, struct latent_alloc, next)->page)->index;
		indexofB = (list_entry(b, struct latent_alloc, next))->page->index;
		if (inodeA < inodeB)
		{
			return -1;
		}
		else if (inodeA == inodeB)
		{
			return indexofA < indexofB ? -1 : 1;
		}
		else
			return 1;
	}
	return 0;
}

// static int __write_data_fsync(struct page *page, bool *submitted,
// 				struct writeback_control *wbc,
// 				enum iostat_type io_type)
// {
// 	struct inode *inode = page->mapping->host;
// 	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
// 	loff_t i_size = i_size_read(inode);
// 	const pgoff_t end_index = ((unsigned long long) i_size)
// 							>> PAGE_SHIFT;
// 	loff_t psize = (page->index + 1) << PAGE_SHIFT;
// 	unsigned offset = 0;
// 	bool need_balance_fs = false;
// 	int err = 0;
// 	struct f2fs_io_info fio = {
// 		.sbi = sbi,
// 		.ino = inode->i_ino,
// 		.type = DATA,
// 		.op = REQ_OP_WRITE,
// 		.op_flags = wbc_to_write_flags(wbc),
// 		.old_blkaddr = NULL_ADDR,
// 		.page = page,
// 		.encrypted_page = NULL,
// 		.submitted = false,
// 		.need_lock = LOCK_RETRY,
// 		.io_type = io_type,
// 	};

// 	trace_f2fs_writepage(page, DATA);

// 	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
// 		goto redirty_out;

// 	if (page->index < end_index)
// 		goto write;

// 	/*
// 	 * If the offset is out-of-range of file size,
// 	 * this page does not have to be written to disk.
// 	 */
// 	offset = i_size & (PAGE_SIZE - 1);
// 	if ((page->index >= end_index + 1) || !offset)
// 		goto out;

// 	zero_user_segment(page, offset, PAGE_SIZE);
// write:
// 	if (f2fs_is_drop_cache(inode))
// 		goto out;
// 	/* we should not write 0'th page having journal header */
// 	if (f2fs_is_volatile_file(inode) && (!page->index ||
// 			(!wbc->for_reclaim &&
// 			available_free_memory(sbi, BASE_CHECK))))
// 		goto redirty_out;

// 	/* we should bypass data pages to proceed the kworkder jobs */
// 	if (unlikely(f2fs_cp_error(sbi))) {
// 		mapping_set_error(page->mapping, -EIO);
// 		goto out;
// 	}

// 	/* Dentry blocks are controlled by checkpoint */
// 	if (S_ISDIR(inode->i_mode)) {//目录文件
// 		fio.need_lock = LOCK_DONE;
// 		err = do_write_data_page(&fio);
// 		goto done;
// 	}

// 	if (!wbc->for_reclaim)
// 		need_balance_fs = true;
// 	else if (has_not_enough_free_secs(sbi, 0, 0))
// 		goto redirty_out;
// 	else
// 		set_inode_flag(inode, FI_HOT_DATA);

// 	err = -EAGAIN;
// 	if (f2fs_has_inline_data(inode)) {
// 		err = f2fs_write_inline_data(inode, page);
// 		if (!err)
// 			goto out;
// 	}

// 	if (err == -EAGAIN) {
// 		err = do_write_data_page(&fio);//普通文件的路径
// 		if (err == -EAGAIN) {
// 			fio.need_lock = LOCK_REQ;
// 			err = do_write_data_page(&fio);
// 		}
// 	}

// 	down_write(&F2FS_I(inode)->i_sem);
// 	if (F2FS_I(inode)->last_disk_size < psize)
// 		F2FS_I(inode)->last_disk_size = psize;
// 	up_write(&F2FS_I(inode)->i_sem);

// done:
// 	if (err && err != -ENOENT)
// 		goto redirty_out;

// out:
// 	inode_dec_dirty_pages(inode);
// 	if (err)
// 		ClearPageUptodate(page);

// 	if (wbc->for_reclaim) {
// 		f2fs_submit_merged_write_cond(sbi, inode, 0, page->index, DATA);
// 		clear_inode_flag(inode, FI_HOT_DATA);
// 		remove_dirty_inode(inode);
// 		submitted = NULL;
// 	}

// 	unlock_page(page);//这个函数没有加锁lock_page
// 	if (!S_ISDIR(inode->i_mode))
// 		f2fs_balance_fs(sbi, need_balance_fs);

// 	if (unlikely(f2fs_cp_error(sbi))) {
// 		f2fs_submit_merged_write(sbi, DATA);
// 		submitted = NULL;
// 	}

// 	if (submitted)
// 		*submitted = fio.submitted;

// 	return 0;

// redirty_out:
// 	redirty_page_for_writepage(wbc, page);
// 	if (!err)
// 		return AOP_WRITEPAGE_ACTIVATE;
// 	unlock_page(page);
// 	return err;
// }
