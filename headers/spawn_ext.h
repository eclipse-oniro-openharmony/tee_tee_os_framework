#ifndef SPAWN_EXT_H
#define SPAWN_EXT_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <tee_uuid.h>

typedef uint64_t cref_t;

typedef int32_t pid_t;
typedef int32_t tid_t;

typedef struct {
} posix_spawn_file_actions_t;

typedef struct spawn_uuid {
    uint64_t uuid_valid;
    TEE_UUID uuid;
} spawn_uuid_t;

typedef struct {
    unsigned version;
    uint64_t stack_size;
    uint64_t heap_size;
    unsigned int flags;
    spawn_uuid_t uuid;
    int32_t ptid;
} posix_spawnattr_t;

int getuuid(pid_t pid, spawn_uuid_t *uuid);

int spawnattr_init(posix_spawnattr_t *attr);

void spawnattr_setuuid(posix_spawnattr_t *attr, const spawn_uuid_t *uuid); 

int spawnattr_setheap(posix_spawnattr_t *attr, size_t size);

int spawnattr_setstack(posix_spawnattr_t *attr, size_t size);

int32_t thread_terminate(pthread_t thread);

int posix_spawn_ex(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_action,
    const posix_spawnattr_t *attrp, char **argv, char **envp, tid_t *tid);

size_t getstacksize(void);

#endif

