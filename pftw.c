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

#include "pftw.h"

char pftw_running;

struct pftw_task {
	char		*path;
	unsigned long	 difficulty;
	struct stat	*stat;

	pftw_queue_t	*queue;
	struct pftw_task *max;
};
typedef struct pftw_task pftw_task_t;

struct pftw_queue {
	pftw_task_t	 tasks[PFTW_MAX_QUEUE_LENGTH];
	void		*tasks_btree;
	int		 tasks_count;
	pftw_callback_t	 callback;
	int		 nopenfd;
	int		 flags;
	void		*arg;
	pthread_mutex_t	 lock;
};
typedef struct pftw_queue pftw_queue_t;

pthread_t *threads       = NULL;
int        threads_count = 0;
sem_t      threads_sem;

/*
pftw_queue_t	*queues  = NULL;
int		 queues_count   = 0;
int		 queues_alloced = 0;
pthread_mutex_t	 queues_lock = PTHREAD_MUTEX_INITIALIZER;
*/

void pftw_worker_dash() {
	
}

void *pftw_worker(void *arg) {
	int ret;

	while (pftw_running) {
		ret = sem_wait(&threads_sem);
		if (ret) {
			pftw_running = 0;
			fprintf(stderr, "pftw internal error #0: %s\n", strerror(errno));
			return (void *)(long)errno;
		}
		pftw_worker_dash();
		ret = sem_post(&threads_sem);
		if (ret) {
			pftw_running = 0;
			fprintf(stderr, "pftw internal error #1: %s\n", strerror(errno));
			return (void *)(long)errno;
		}
	}

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

	threads = calloc(num_threads, sizeof(pthread_t));

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
			pthread_create(&threads[i], NULL, pftw_worker, NULL);

			i++;
		}

		threads_count = num_threads;
	}

	return 0;
}

int pftw_deinit() {
	if (!pftw_running)
		return ENOENT;

	// No more iterations for pftw workers
	pftw_running = 0;

	{
		int i;

		// Interrupting sem_wait()
		i = 0;
		while (i < threads_count) {
			int ret = pthread_kill(threads[i], SIGCONT);
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

	free(queues);
	queues		= NULL;
	queues_count	= 0;
	queues_alloced	= 0;

	return sem_destroy(&threads_sem);
}

static inline void lock_queues() {
	//pthread_mutex_lock(&queues_lock);
	return;
}

static inline void unlock_queues() {
	//pthread_mutex_unlock(&queues_lock);
	return;
}

static inline void lock_queue(pftw_queue_t *queue) {
	lock_queues();
	pthread_mutex_lock(&queue->lock);
	return;
}

static inline void unlock_queue(pftw_queue_t *queue) {
	pthread_mutex_unlock(&queue->unlock);
	unlock_queues();
	return;
}

pftw_queue_t *pftw_newqueue(pftw_callback_t callback, int nopenfd, int flags) {
	lock_queues();
/*
	int queue_id = queues_count;

	if (queue_id >= queues_alloced) {
		queues_alloced += PFTW_ALLOCPORTION;
		queues		= realloc(queues, queues_alloced);

		if (queues == NULL) {
			unlock_queues();
			return NULL;
		}
	}

	queues_count++;

	pftw_queue_t *queue = &queues[queue_id];*/

	pftw_queue_t *queue = malloc(sizeof(*queue));
	if (queue == NULL)
		return NULL;

	queue->tasks_count	= 0;
	queue->callback		= callback;
	queue->nopenfd		= nopenfd;
	queue->flags		= flags;
	queue->tasks_btree	= NULL;
	queue->arg		= arg;

	pthread_mutex_init(&queue->lock, NULL);

	unlock_queues();
	return queue;
}

int pftw_deletequeue(pftw_queue_t *queue) {
	lock_queues();

	if (queue->tasks_count > 0) {
		unlock_queues();
		return EBUSY;
	}

	pthread_mutex_destroy(&queue->lock);

	tdestroy(queue->tasks_btree);

	//memcpy(queue, &queues[--queues_count], sizeof(*queue));
	free(queue);

	unlock_queues();
	return 0;
}

static int tasks_difficultycmp_findmax(const void *task_a, const void *task_b) {
	if (tasks_a->difficulty > tasks_b->difficulty) {
		tasks_a->max = tasks_b;
		return 1;
	}
	if (tasks_a->difficulty < tasks_b->difficulty) {
		tasks_b->max = tasks_a;
		return -1;
	}

	return 0;
}

static int tasks_difficultycmp(const void *task_a, const void *task_b) {
	if (tasks_a->difficulty > tasks_b->difficulty)
		return 1;
	if (tasks_a->difficulty < tasks_b->difficulty)
		return -1;

	return 0;
}

int pftw_pushtask(pftw_queue_t *queue, const char *dirpath, unsigned long difficulty) {
	lock_queue(queue);

	if (queue->tasks_count >= PFTW_MAX_QUEUE_LENGTH) {
		unlock_queue(queue);
		return EBUSY;
	}

	pftw_task_t *task = &queue->tasks[queue->tasks_count++];
	task->dirpath     = strdup(dirpath);
	task->queue	  = queue;

	{	// TODO: Remove this magic with the difficulty. It's just hacks to prevent key collision in the tree. First bits is a real difficulty. The last bits is just a task_id for the prevention.
		unsigned long difficulty_overload_mask = ~((1 << (sizeof(difficulty)*8) - (PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS)) - 1);
		unsigned long difficulty_task_id_mask  =   (1 << (PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS)) - 1;

		if (difficulty & difficulty_overload_mask)
			task->difficulty = ~difficulty_task_id_mask;
		else
			task->difficulty = difficulty << (PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS);

		task->difficulty |= queue->tasks_id++;
		queue->task_id %= PFTW_MAX_QUEUE_LENGTH;
	}


	while (1) {
		void *found = tsearch(task, &queue->tasks_btree, tasks_difficultycmp);
		if (found == NULL) {
			unlock_queue(queue);
			return ENOMEM;
		}

		if (found != task) {	// TODO: Remove this. This is a hack to retry on key collision in the tree
			task->difficulty &= ~difficulty_task_id_mask;
			task->difficulty |= queue->tasks_id++;
			queue->task_id %= PFTW_MAX_QUEUE_LENGTH;

			continue;
		}
		break;
	}

	unlock_queue(queue);

	return 0;
}

pftw_task_t *pftw_poptask(pftw_queue_t *queue) {
	lock_queue(queue);

	if (queue->tasks_count <= 0) {
		unlock_queue(queue);
		return NULL;
	}

	pftw_task_t max_key, *max;

	max_key->difficulty = ~0;

	void *found = tfind(&max_key, &queue->btree, tasks_difficultycmp_findmax);	// Searching for the most difficult task

	max = max_key->max;

	unlock_queue(queue);

	return max;
}

int pftw_dotask_processentry(pftw_task_t *task, struct dirent *entry_p) {
	struct stat stat;
	pftw_queue_t *queue = task->queue;
	int flags = queue->flags;

	if (flags & FTW_PHYS)
		lstat(entry_p->d_name, &stat);
	else 
		stat (entry_p->d_name, &stat);

	// TODO: check for recursion

	char follow = (stat.d_type == DT_DIR);

	if (flags & FTW_MOUNT)
		if (task->stat.st_dev != stat.st_dev)
			follow = 0;

	char path = ;

	int rc = queue->callback(path, &stat, ftw_ftype, NULL, queue->arg);
	if (flags & FTW_ACTIONRETVAL) {
		switch (rc) {
			case FTW_CONTINUE:
				break;
			case FTW_SKIP_SUBTREE:
				break;
			case FTW_SKIP_SIBLINGS:
				fprintf(stderr, "At the moment FTW_SKIP_SIBLINGS is not supported by pftw().\n");
			case FTW_STOP:
				break;
		}
	}
}


int pftw_dotask(pftw_task_t *task) {
	DIR *dir = opendir(task->dirpath);
	struct dirent entry, *readdir_result;
	pftw_queue_t *queue = task->queue;

	if (task->stat.st_nlink == 0) {	// If stat() is not done, yet
		int flags = queue->flags;

		if (flags & FTW_PHYS)
			lstat(entry_p->d_name, &task->stat);
		else 
			stat (entry_p->d_name, &task->stat);
	}

	while (1) {
		int rc = readdir_r(dir, &entry, &readdir_result);
		if (rc) return rc;
		if (result == NULL)
			break;

		rc = pftw_dotask_processentry(task, &entry);
		if (rc) return rc;
	}

	closedir(dir);
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

	int rc = pftw_pushtask(queue, dirpath, ~0);
	if (rc) return rc;

	pftw_task_t *task;
	while ((task = pftw_poptask(queue)) != NULL) {
		rc = pftw_dotask(task);
		if (rc) return rc;
	}

	rc = pftw_deletequeue(queue);
	if (rc) return rc;

	return 0;
}

