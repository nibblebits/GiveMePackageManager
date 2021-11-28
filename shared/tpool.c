#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "tpool.h"
#include "log.h"
#include "vector.h"
pthread_t *threads = NULL;
size_t t_threads = 0;
struct vector *queued_work_vec;
pthread_mutex_t queued_work_vec_lock;

void *giveme_thread(void *arg)
{
    while (1)
    {
        struct queued_work *work = NULL;
        pthread_mutex_lock(&queued_work_vec_lock);
        work = vector_back_ptr_or_null(queued_work_vec);
        if (work)
        {
            vector_pop(queued_work_vec);
        }

        pthread_mutex_unlock(&queued_work_vec_lock);

        if (work)
        {
            // We have some popped work
            work->function(work);
            // Work is done lets delete the work
            free(work);
        }
        sleep(1);
    }
}

void giveme_queue_work(QUEUED_WORK_FUNCTION function, void *private)
{
    struct queued_work* work = calloc(1, sizeof(struct queued_work));
    work->function = function;
    work->private = private;
    pthread_mutex_lock(&queued_work_vec_lock);
    vector_push(queued_work_vec, &work);
    pthread_mutex_unlock(&queued_work_vec_lock);
}

void giveme_thread_pool_start()
{
    for (size_t i = 0; i < t_threads; i++)
    {
        pthread_create(&threads[i], NULL, giveme_thread, NULL);
    }
}
int giveme_thread_pool_init(size_t _t_threads)
{
    t_threads = _t_threads;
    threads = calloc(t_threads, sizeof(pthread_t));
    queued_work_vec = vector_create(sizeof(struct queued_work *));

    if (pthread_mutex_init(&queued_work_vec_lock, NULL) != 0)
    {
        giveme_log("Failed to initialize thread pool lock mutex\n");
        return 1;
    }
}
