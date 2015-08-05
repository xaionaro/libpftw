/*
    libpftw — parallel file tree walk library
    
    Copyright (C) 2015 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <semaphore.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>	/* fprintf() */
#include <string.h>	/* strerror() */
#include <stdlib.h>
#include <search.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include "pftw.h"

#ifdef DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) {}
#endif

char pftw_running;

struct pftw_task {
	char		dirpath[PATH_MAX];
	size_t		dirpath_len;
	unsigned long	difficulty;
	struct stat	stat;

	struct pftw_queue *queue;
	struct pftw_task *max;
};
typedef struct pftw_task pftw_task_t;

struct pftw_queue {
	int		 id;
	pftw_task_t	*tasks[PFTW_MAX_QUEUE_LENGTH];
	void		*tasks_btree;
	int		 tasks_count;
	int		 current_task_id;
	pftw_callback_t	 callback;
	int		 nopenfd;
	int		 flags;
	void		*arg;
	pthread_mutex_t	 lock;
	sem_t		 ending_sem;
	int		 workers[PFTW_MAX_THREADS];
	int		 workers_count;
};
typedef struct pftw_queue pftw_queue_t;

pthread_t	 *threads	 = NULL;
int		  threads_count	 = 0;
sem_t		  threads_sem;
pftw_queue_t	**thread_queue	 = NULL;
pftw_queue_t	**queues	 = NULL;
int		  queues_count	 = 0;
int		  queues_alloced = 0;
pthread_mutex_t	  queues_lock	 = PTHREAD_MUTEX_INITIALIZER;

/*
pftw_queue_t	*queues  = NULL;
int		 queues_count   = 0;
*/

static inline void lock_queues() {
	dprintf("lock queues\n");
	pthread_mutex_lock(&queues_lock);
	dprintf("locked queues\n");
	return;
}

static inline void unlock_queues() {
	dprintf("unlock queues\n");
	pthread_mutex_unlock(&queues_lock);
	return;
}

static inline int alsolock_queue(pftw_queue_t *queue) {
	int i = 0;
	while (i < queues_count)
		if (queues[i] == queue) {
			dprintf("lock %p\n", queue);
			pthread_mutex_lock(&queue->lock);
			dprintf("locked %p, tasks: %i\n", queue, queue->tasks_count);
			return 0;
		}
	return ENOENT;
}

static inline int lock_queue(pftw_queue_t *queue) {
	lock_queues();
	return alsolock_queue(queue);
}

static inline void unlock_queue(pftw_queue_t *queue) {
	dprintf("unlock %p\n", queue);
	pthread_mutex_unlock(&queue->lock);
	unlock_queues();
	return;
}

pftw_queue_t *pftw_newqueue(pftw_callback_t callback, int nopenfd, int flags, void *arg) {
	lock_queues();

	int queue_id = queues_count;

	if (queue_id >= queues_alloced) {
		queues_alloced += PFTW_ALLOCPORTION;
		queues		= realloc(queues, queues_alloced*sizeof(*queues));

		if (queues == NULL) {
			unlock_queues();
			return NULL;
		}
	}

	queues_count++;

	pftw_queue_t *queue = malloc(sizeof(*queue));
	if (queue == NULL)
		return NULL;

	queues[queue_id]	= queue;

	queue->id		= queue_id;
	queue->tasks_count	= 0;
	queue->callback		= callback;
	queue->nopenfd		= nopenfd;
	queue->flags		= flags;
	queue->tasks_btree	= NULL;
	queue->arg		= arg;
	queue->current_task_id	= 0;
	queue->workers_count	= 0;

	pthread_mutex_init(&queue->lock, NULL);
	sem_init(&queue->ending_sem, 0, 1);

	unlock_queues();
	return queue;
}

/*void free_noop(void *arg) {
	return;
}*/

int pftw_deletequeue(pftw_queue_t *queue) {
	lock_queues();

	if (queue->tasks_count > 0) {
		unlock_queues();
		return EBUSY;
	}

	pthread_mutex_destroy(&queue->lock);

	tdestroy(queue->tasks_btree, free);

	int i;
	i = 0;
	while (i < queue->workers_count)
		thread_queue[queue->workers[i++]] = NULL;

	queues[queue->id]     = queues[--queues_count];
	queues[queue->id]->id = queue->id;

	free(queue);

	unlock_queues();
	return 0;
}

static int tasks_difficultycmp_findmax(const void *_task_a, const void *_task_b) {
	pftw_task_t *task_a = (pftw_task_t *)_task_a, *task_b = (pftw_task_t *)_task_b;

	dprintf("max: %s|%s|%lu (%p, %p)\n", task_a->dirpath, task_b->dirpath, task_b->difficulty, task_a->max, task_b->max);

	if (task_a->difficulty > task_b->difficulty) {
		if (task_a->max != NULL)
			if (task_a->max->difficulty > task_b->difficulty)
				return 1;
		task_a->max = task_b;
		return 1;
	}
	if (task_a->difficulty < task_b->difficulty) {
		if (task_b->max != NULL)
			if (task_b->max->difficulty > task_a->difficulty)
				return -1;
		task_b->max = task_a;
		return -1;
	}

	if (task_a->max == NULL)
		task_a->max = task_b;

	if (task_b->max == NULL)
		task_b->max = task_a;
	return 0;
}

static int tasks_difficultycmp(const void *_task_a, const void *_task_b) {
	const pftw_task_t *task_a = _task_a, *task_b = _task_b;

	dprintf("%s|%s|%lu\n", task_a->dirpath, task_b->dirpath, task_b->difficulty);

	if (task_a->difficulty > task_b->difficulty)
		return 1;
	if (task_a->difficulty < task_b->difficulty)
		return -1;

	return 0;
}

int pftw_pushtask(pftw_queue_t *queue, const char *dirpath, size_t dirpath_len, struct stat *st, unsigned long difficulty) {
	dprintf("pftw_pushtask(): \"%s\"\n", dirpath);
	int rc = lock_queue(queue);
	if (rc)
		return (rc == ENOENT ? 0 : rc);

	if (queue->tasks_count >= PFTW_MAX_QUEUE_LENGTH) {
		unlock_queue(queue);
		return EBUSY;
	}

	pftw_task_t **task_p = &queue->tasks[queue->tasks_count++];

	*task_p = calloc(1, sizeof(**task_p));
	if (*task_p == NULL)
		return ENOMEM;

	pftw_task_t *task = *task_p;

	strcpy(task->dirpath, dirpath);
	task->dirpath_len = dirpath_len;
	task->queue	  = queue;

	if (st == NULL)
		memset(&task->stat, 0,  sizeof(task->stat));
	else
		memcpy(&task->stat, st, sizeof(task->stat));

	// TODO: Remove this magic with the difficulty. It's just hacks to prevent key collision in the tree. First bits is a real difficulty. The last bits is just a task_id for the prevention.
	int difficulty_bitpos_edge = PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS;

	unsigned long difficulty_overload_mask;
	difficulty_overload_mask   = ~0;
	difficulty_overload_mask <<= sizeof(difficulty)*8 - difficulty_bitpos_edge;

	unsigned long difficulty_task_id_mask;
	difficulty_task_id_mask    = ~0;
	difficulty_task_id_mask  <<=  difficulty_bitpos_edge;
	difficulty_task_id_mask    = ~difficulty_task_id_mask;

	if (difficulty & difficulty_overload_mask)
		task->difficulty = ~difficulty_task_id_mask;
	else
		task->difficulty = difficulty << (PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS);

	task->difficulty |= queue->current_task_id++;
	task->max         = NULL;
	queue->current_task_id %= PFTW_MAX_QUEUE_LENGTH;

	dprintf("pftw_pushtask(): \"%s\" (%i): %lu\n", dirpath, queue->tasks_count, task->difficulty);


	while (1) {
		void *found = tsearch(task, &queue->tasks_btree, tasks_difficultycmp);
		if (found == NULL) {
			unlock_queue(queue);
			return ENOMEM;
		}

		if (found == task) {	// TODO: Remove this. This is a hack to retry on key collision in the tree
			task->difficulty &= ~difficulty_task_id_mask;
			task->difficulty |= queue->current_task_id++;
			queue->current_task_id %= PFTW_MAX_QUEUE_LENGTH;

			continue;
		}
		break;
	}

	unlock_queue(queue);

	return sem_post(&threads_sem);
}

int pftw_poptask(pftw_queue_t *queue, pftw_task_t *task) {
	int rc = lock_queue(queue);
	if (rc) {
		unlock_queue(queue);
		if (rc == ENOENT)
			return ENOENT;
		fprintf(stderr, "Unknown internal error #3 of ftw()\n");
		return rc;
	}

	if (queue->tasks_count <= 0) {
		unlock_queue(queue);
		return ENOENT;
	}

	pftw_task_t max_key = {{0}};

	//strcpy(max_key.dirpath, "JUST A TEST");
	max_key.difficulty = ~0;
	//max_key.difficulty = 1000000;

	void *found = tfind(&max_key, &queue->tasks_btree, tasks_difficultycmp_findmax);	// Searching for the most difficult task

	assert (found == NULL);
	assert (max_key.max != NULL);

	memcpy(task, max_key.max, sizeof(*task));
	dprintf("pftw_poptask(): \"%s\": %lu\n", task->dirpath, task->difficulty);

	found = tdelete(max_key.max, &queue->tasks_btree, tasks_difficultycmp);
	if (found == NULL) {
		fprintf(stderr, "Unknown internal error #4 of ftw()\n");
		unlock_queue(queue);
		return ENOENT;
	}

	//size_t task_inqueueid = (max_key.max - queue->tasks) / sizeof(*task);

	--queue->tasks_count;
	free(max_key.max);
	//if (task_inqueueid != queue->tasks_count)
	//	memcpy(&queue->tasks[task_inqueueid], &queue->tasks[queue->tasks_count], sizeof(*queue->tasks));

	dprintf("pftw_poptask(): \"%s\" (%i)\n", task->dirpath, queue->tasks_count);
	unlock_queue(queue);
	return 0;
}

int pftw_dotask(pftw_task_t *task);

int pftw_dotasknow(pftw_queue_t *queue, const char *path, size_t path_len, struct stat *st_p) {
	pftw_task_t childtask;

	strcpy(childtask.dirpath, path);
	childtask.dirpath_len = path_len;
	childtask.queue       = queue;
	memcpy(&childtask.stat, st_p, sizeof(*st_p));

	return pftw_dotask(&childtask);
}

int pftw_dotask_processentry(pftw_task_t *task, struct dirent *entry_p) {
	struct stat st;
	pftw_queue_t *queue = task->queue;
	int flags = queue->flags;
	int rc;

	// Getting path
	size_t entry_d_name_len = strlen(entry_p->d_name);

	size_t path_len = task->dirpath_len + 1 + entry_d_name_len;
	char path[PATH_MAX+1];

	if (path_len > PATH_MAX) {
		fprintf(stderr, "pftw internal error #6\n");
		return ENAMETOOLONG;
	}

	memcpy(path, task->dirpath, task->dirpath_len);
	path[task->dirpath_len] = '/';
	memcpy(&path[task->dirpath_len + 1], entry_p->d_name, entry_d_name_len);
	path[path_len] = 0;

	// Getting stat

	dprintf("pftw_dotask_processentry(): \"%s\" (%lu) of \"%s\" (%lu) is (%lu) \"%s\"\n", entry_p->d_name, entry_d_name_len, task->dirpath, task->dirpath_len, path_len, path);

	if (flags & FTW_PHYS)
		rc = lstat(path, &st);
	else 
		rc = stat (path, &st);

	if (rc)	return errno;

	// TODO: check for recursion

	char follow = (entry_p->d_type == DT_DIR);

	if (flags & FTW_MOUNT)
		if (task->stat.st_dev != st.st_dev)
			follow = 0;

	int ftw_ftype = FTW_NS;
	switch (entry_p->d_type) {
		case DT_BLK:
		case DT_CHR:
		case DT_FIFO:
		case DT_LNK:
		case DT_REG:
		case DT_SOCK:
			ftw_ftype = FTW_F;
			break;
		case DT_DIR:
			ftw_ftype = FTW_D;
			break;
		case DT_UNKNOWN:
			ftw_ftype = FTW_NS;
			break;
	}

	rc = queue->callback(path, &st, ftw_ftype, NULL, queue->arg);
	if (flags & FTW_ACTIONRETVAL) {
		switch (rc) {
			case FTW_CONTINUE:
				break;
			case FTW_SKIP_SUBTREE:
				follow = 0;
				break;
			case FTW_SKIP_SIBLINGS:
				fprintf(stderr, "At the moment FTW_SKIP_SIBLINGS is not supported by pftw().\n");
				break;
			case FTW_STOP:
				fprintf(stderr, "At the moment FTW_STOP is not supported by pftw().\n");
				break;
		}
	}

	if (follow) {
		int rc;
		unsigned long difficulty = st.st_nlink;

		if (difficulty >= PFTW_DIFFICULTY_THRESHOLD) {	// If the task is heavy then public it for workers
			rc = pftw_pushtask(queue, path, path_len, &st, difficulty);
			if (rc == EBUSY)
				rc = pftw_dotasknow(queue, path, path_len, &st);
		} else {					// Otherwise do the task by myself
			rc = pftw_dotasknow(queue, path, path_len, &st);
		}
		if (rc) return rc;
	}

	return 0;
}


int pftw_dotask(pftw_task_t *task) {
	dprintf("opendir(%s)\n", task->dirpath);
	DIR *dir = opendir(task->dirpath);
	pftw_queue_t *queue = task->queue;

	if (dir == NULL) {
		switch (errno) {
			case EACCES:
				queue->callback(task->dirpath, &task->stat, FTW_DNR, NULL, queue->arg);
				return 0;
			default:
				return errno;
		}
	}

	struct dirent entry, *readdir_result;

	if (task->stat.st_nlink == 0) {	// If stat() is not done, yet
		int rc;
		int flags = queue->flags;

		if (flags & FTW_PHYS)
			rc = lstat(task->dirpath, &task->stat);
		else 
			rc = stat (task->dirpath, &task->stat);
		if (rc)
			return rc;
	}

	while (1) {
		int rc = readdir_r(dir, &entry, &readdir_result);
		if (rc) return rc;
		if (readdir_result == NULL)
			break;

		if (entry.d_name[0] == '.' && (entry.d_name[1] == 0 || (entry.d_name[1] == '.' && entry.d_name[2] == 0)))
			continue;	// Skip "." and ".."

		rc = pftw_dotask_processentry(task, &entry);
		if (rc) return rc;
	}

	closedir(dir);

	return 0;
}

int pftw(const char *dirpath, pftw_callback_t fn, int nopenfd, int flags, void *arg) {
	if (!pftw_running)
		return EBUSY;

	if (flags & ~(FTW_ACTIONRETVAL|FTW_MOUNT|FTW_PHYS))	// Check if all flags are supported flags
		return EINVAL;

	if (!(flags & FTW_PHYS)) {	// Recursion anti-loop is not implemented. Symlinks are too often dangerous.
		fprintf(stderr, "At the moment pftw() cannot be used without flag FTW_PHYS.\n");
		return EINVAL;
	}

	pftw_queue_t *queue = pftw_newqueue(fn, nopenfd, flags, arg);
	if (queue == NULL)
		return errno;

	int rc = pftw_pushtask(queue, dirpath, strlen(dirpath), NULL, ~0);
	if (rc == EBUSY) {
		fprintf(stderr, "This case is not implemented, yet\n");
	}
	if (rc) return rc;

	pftw_task_t task;
	while ((rc = pftw_poptask(queue, &task)) == 0) {
		rc = pftw_dotask(&task);
		if (rc) return rc;
	}
	if (rc && rc != ENOENT) return rc;

	while (queue->workers_count > 0) {
		dprintf("pftw(): queue->workers_count == %i\n", queue->workers_count);
		sem_wait(&queue->ending_sem);
	};

	rc = pftw_deletequeue(queue);
	if (rc) return rc;

	return 0;
}


void pftw_worker_dash(int worker_id) {
	int rc;
	dprintf("pftw_worker_dash(%i)\n", worker_id);

	do {
		pftw_queue_t *queue;
		if (queues_count == 0) {
			return;
		}

		queue = thread_queue[worker_id];

		if (queue == NULL) {
			lock_queues();

			if (queues_count == 0) {
				unlock_queues();
				return;
			}

			int queue_id = worker_id % queues_count;

			dprintf("pftw_worker_dash(%i): queue_id == %i\n", worker_id, queue_id);

			thread_queue[worker_id] = queues[queue_id];
			queue = thread_queue[worker_id];

			queue->workers[queue->workers_count++] = worker_id;

			unlock_queues();
		}

		pftw_task_t task;
		rc = pftw_poptask(queue, &task);
		switch (rc) {
			case 0:
				rc = pftw_dotask(&task);
				if (rc) {
					fprintf(stderr, "pftw internal error #1: %s\n", strerror(errno));
					return;
				}
				break;
			case ENOENT:
				break;
			default:
				fprintf(stderr, "pftw internal error #5: %s\n", strerror(errno));
				return;
		}
		dprintf("pftw_worker_dash(%i): %i\n", worker_id, rc);
	} while (rc == 0);

	return;
}

void *pftw_worker(void *_arg) {
	int worker_id = (long)_arg;
	int ret;

	ret = sem_wait(&threads_sem);
	while (pftw_running) {
		pftw_worker_dash(worker_id);
		dprintf("worker %i: sem_wait(): pftw_running == %i; %p\n", worker_id, pftw_running, thread_queue[worker_id]);

		if (thread_queue[worker_id] != NULL) {
			pftw_queue_t *queue = thread_queue[worker_id];
			int rc = lock_queue(queue);
			if (!rc) {
				{
					int i;
					i = 0;
					while (i < queue->workers_count) {
						if (queue->workers[i] == worker_id) {
							queue->workers[i] = queue->workers[--queue->workers_count];
							break;
						}
						i++;
					}
				}
				sem_post(&queue->ending_sem);
				unlock_queue(queue);
			}
			thread_queue[worker_id] = NULL;
		}

		ret = sem_wait(&threads_sem);
		if (ret) {
			pftw_running = 0;
			fprintf(stderr, "pftw internal error #0: %s\n", strerror(errno));
			return (void *)(long)errno;
		}
	}

	dprintf("worker %i finished (%i)\n", worker_id, pftw_running);
	return NULL;
}

int pftw_init(int num_threads) {

	if (num_threads < 2)
		return EINVAL;

	if (num_threads > PFTW_MAX_THREADS)
		return EINVAL;

	num_threads--;	// One thread is the master thread [pftw()]

	if (pftw_running) {
		return EBUSY;
	}

	threads		= calloc(num_threads, sizeof(pthread_t));
	thread_queue	= calloc(num_threads, sizeof(void *));

	if (threads == NULL)
		return ENOMEM;

	int ret = sem_init(&threads_sem, 0, num_threads);
	if (ret) {
		free(threads);
		return errno;
	}

	pftw_running = 1;

	{
		int i = 0;
		while (i < num_threads) {
			pthread_create(&threads[i], NULL, pftw_worker, (void *)(long)i);

			i++;
		}

		threads_count = num_threads;
	}

	return 0;
}

int pftw_deinit() {
	dprintf("pftw_deinit()\n");

	if (!pftw_running)
		return ENOENT;

	// No more iterations for pftw workers
	pftw_running = 0;

	{
		int i;

		// Interrupting sem_wait()
		i = 0;
		while (i < threads_count) {
//			int ret = pthread_kill(threads[i], SIGCONT);
			int ret = sem_post(&threads_sem);
			if (ret)
				return ret;
			i++;
		}

		// Waiting for finish
		i = 0;
		while (i < threads_count) {
			int ret;
			void *retval;
			ret = pthread_join(threads[i], &retval);
			if (ret)
				return ret;
			i++;
		}
	}

	// Clean up
	free(threads);
	threads		= NULL;
	threads_count	= 0;

	free(thread_queue);
	thread_queue	= NULL;

	{
		int i;

		i = 0;
		while (i < queues_count)
			free(queues[i++]);

		free(queues);
		queues		= NULL;
		queues_count	= 0;
		queues_alloced	= 0;
	}

	return sem_destroy(&threads_sem);
}

