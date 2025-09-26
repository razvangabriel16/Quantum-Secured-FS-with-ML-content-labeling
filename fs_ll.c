#define FUSE_USE_VERSION 35

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>

//#define MAX_NAME_LEN 255
#define MAX_NAME_LEN 400
#define INODE_HASH_SIZE 4096
#define MAX_INODES 65536
#define BLOCK_SIZE 4096
#define MEMORY_POOL_SIZE (64 * 1024 * 1024)
#define CACHE_TIMEOUT 60.0
#define INODE_DIRTY 0x01
#define INODE_CACHED 0x02
#define INODE_DELETED 0x04
#define DEBUG_MESS_ACTIVE "Active Debug!\n"
#define ENCRYPTED_BIT 0x00010000

typedef struct fs_dirent{
    char name[MAX_NAME_LEN];
    fuse_ino_t ino;
    mode_t type;
    struct fs_dirent* next;
}fs_dirent_t;

typedef struct fs_inode{
    fuse_ino_t ino;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    off_t size;
    blkcnt_t blocks;
    struct timespec atime, mtime, ctime;
    union{
        struct {
            void* data;
            size_t allocated;
            size_t capacity;
            uint8_t is_encrypted;
        } file;
        struct {
            fs_dirent_t* entries;
            size_t entry_count;
        } dir;
        struct {
            char* target;
        } link;
    };
    atomic_int refcount;
    atomic_int access_count;
    struct fs_inode* lru_n, *lru_p;
    struct fs_inode* hash_n;
    int flags;
    time_t cache_time;
}fs_inode_t;

typedef struct{
    void* base;
    size_t size;
    size_t used;
    size_t max_used;
    struct free_block{
        size_t size;
        struct free_block* next;
    }*free_list;
    atomic_int allocations;
    atomic_int deallocations;
    atomic_int bytes_allocated;
}memory_pool_t;

typedef struct{
    fs_inode_t* hashtable[INODE_HASH_SIZE];
    fs_inode_t* lru_head, *lru_tail;
    size_t cached_count;
    size_t max_cached;
    atomic_llong hits;
    atomic_llong misses;
    atomic_llong evictions;
}inode_cache_t;

typedef struct {
    struct fuse_session *fuse_se;
    inode_cache_t* cache;
    memory_pool_t* memory_pool;
    atomic_llong next_ino;
    unsigned char shutdown;
    atomic_llong total_requests;
    atomic_llong errors;
    atomic_llong cache_hits;
    double attr_timeout;
    double entry_timeout;
}fs_session_t;

typedef struct block_header {
    size_t size;
    unsigned char data[];
} block_header_t;

int set_memory_pool(memory_pool_t** mempool, size_t size){
    if(((*mempool)->base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) return 0;
    (*mempool)->size = size;
    (*mempool)->used = 0;
    (*mempool)->max_used = 0;
    (*mempool)->free_list = (struct free_block*)((*mempool)->base);
    (*mempool)->free_list->size = size;
    (*mempool)->free_list->next = NULL;
    atomic_init((&(*mempool)->allocations), 0);
    atomic_init((&(*mempool)->deallocations), 0);
    atomic_init((&(*mempool)->bytes_allocated), 0);
    return 1;
}

//void cleanup_filesystem(fs_session_t* globalfs){
//   //TODO
//}

void* fs_malloc(fs_session_t* globalfs, size_t size){
    memory_pool_t* mempool = globalfs->memory_pool;
    size_t total_size = sizeof(block_header_t) + ((size + 7) & ~7);
    struct free_block** prev = &(mempool->free_list);
    for(struct free_block* cur = mempool->free_list; cur; prev = &cur->next, cur = cur->next) {
        if(cur->size >= total_size){
            size_t rest = cur->size - total_size;
            if(rest >= sizeof(struct free_block) + 8){
                struct free_block* new_free = (struct free_block*)((unsigned char*)cur + total_size);
                new_free->size = rest;
                new_free->next = cur->next;
                *prev = new_free;
            } else {
                total_size = cur->size;
                *prev = cur->next;
            }
            block_header_t* header = (block_header_t*)cur;
            header->size = total_size;
            mempool->used += total_size;
            if(mempool->used > mempool->max_used) mempool->max_used = mempool->used;
            atomic_fetch_add(&mempool->allocations, 1);
            atomic_fetch_add(&mempool->bytes_allocated, total_size);
            return header->data; //sau (char*)header + sizeof(block_header_t)
        }
    }
    return NULL;
}

int fs_free(fs_session_t* globalfs, void* ptr){
    if(!ptr) return 1;
    memory_pool_t* mempool = globalfs->memory_pool;
    block_header_t* curheader = (block_header_t*)((unsigned char*)ptr - sizeof(block_header_t)); 
    size_t block_size = curheader->size;
    if((unsigned char*)curheader < (unsigned char*)mempool->base ||
        (unsigned char*)curheader >= (unsigned char*) mempool->base + mempool->size) return 2;
    struct free_block* freeb = (struct free_block*)curheader;
    freeb->size = block_size;
    struct free_block* cur = mempool->free_list;
    struct free_block** prev = &mempool->free_list;
    while(cur && cur < freeb){
        prev = &cur->next;
        cur = cur->next;
    }
    freeb->next = cur;
    *prev = freeb;

    if(freeb->next != NULL && ((unsigned char*)freeb + freeb->size) == (unsigned char*)(freeb->next))
    {   freeb->size += freeb->next->size;
        freeb->next = freeb->next->next;
    }

    if(((unsigned char*)(*prev) + (*prev)->size) == (unsigned char*)freeb)
    {   
        (*prev)->size += freeb->size;
        (*prev)->next = freeb->next;
    }

    mempool->used -= block_size;
    atomic_fetch_add(&mempool->deallocations, 1);
    return 0;
}

void inode_put(fs_session_t* global_fs, fs_inode_t* inode){
    if(!inode) return;
    if(atomic_fetch_sub(&inode->refcount, 1)==1){
        if(S_ISREG(inode->mode) && inode->file.data)
            fs_free(global_fs, inode->file.data);
        else if(S_ISDIR(inode->mode)){
            fs_dirent_t* entry = inode->dir.entries;
            while(entry){
                fs_free(global_fs, entry);
                entry = entry->next;
            }
        }else if(S_ISLNK(inode->mode) && inode->link.target)
            fs_free(global_fs, inode->link.target);
        fs_free(global_fs, inode);
    }
}
void cleanup_session(struct fuse_session* session, struct fuse_cmdline_opts* opts, 
                    struct fuse_args* args, int return_value){
    fuse_session_destroy(session);
    free(opts->mountpoint);
    fuse_opt_free_args(args);
//    cleanup_filesystem();
    if(return_value) exit;
}

void remove_handlers(struct fuse_session* session, struct fuse_cmdline_opts* opts, 
                    struct fuse_args* args, int return_value){

    fuse_remove_signal_handlers(session);
    cleanup_session(session, opts, args, return_value);
}

static inline int get_hashed_ino(fuse_ino_t inode){
    return inode % INODE_HASH_SIZE;
}


static void inodecache_add(fs_session_t* global_fs, fs_inode_t* ino) {
    inode_cache_t* cache = global_fs->cache;
    if (ino->ino == cache->lru_head->ino || ino->ino == cache->lru_tail->ino) return;
    if (ino->flags & INODE_CACHED) return;
    size_t hashed = get_hashed_ino(ino->ino);
    ino->hash_n = cache->hashtable[hashed];
    cache->hashtable[hashed] = ino;
    ino->lru_n = cache->lru_head->lru_n;
    ino->lru_p = cache->lru_head;
    cache->lru_head->lru_n->lru_p = ino;
    cache->lru_head->lru_n = ino;
    cache->cached_count++;
    ino->flags |= INODE_CACHED;
    ino->cache_time = time(NULL);
}


static fs_inode_t* inodecache_lookup(fs_session_t* global_fs, fuse_ino_t ino) {
    inode_cache_t* cache = global_fs->cache;
    size_t hashed = get_hashed_ino(ino);
    if (ino == cache->lru_head->ino || ino == cache->lru_tail->ino) return NULL;
    fs_inode_t* found = NULL;
    fs_inode_t* prev = NULL;
    for (fs_inode_t* current = cache->hashtable[hashed]; current; prev = current, current = current->hash_n) {
        if (current->ino == ino) {
            found = current;
            break;
        }
        if (current == current->hash_n) {
            if (prev) prev->hash_n = NULL;
            break;
        }
    }
    if (found) {
        if (found->lru_p) found->lru_p->lru_n = found->lru_n;
        if (found->lru_n) found->lru_n->lru_p = found->lru_p;
        found->lru_n = cache->lru_head->lru_n;
        found->lru_p = cache->lru_head;
        cache->lru_head->lru_n->lru_p = found;
        cache->lru_head->lru_n = found;
        atomic_fetch_add(&cache->hits, 1);
        return found;
    }
    atomic_fetch_add(&cache->misses, 1);
    return NULL;
}

fs_inode_t* inodecache_get(fs_session_t* global_fs, fuse_ino_t inode){
    fs_inode_t* curino = inodecache_lookup(global_fs, inode);
    if(!curino && inode == FUSE_ROOT_ID){
        curino = ( fs_inode_t*)malloc(sizeof(fs_inode_t)); // fs_malloc(global_fs, sizeof(fs_inode_t));
        if(!curino) return NULL;
        memset(curino, 0, sizeof(fs_inode_t));
        curino->ino = FUSE_ROOT_ID;
        curino->mode = __S_IFDIR | 0755;
        curino->nlink = 2;
        curino->uid = getuid();
        curino->gid = getgid();
        clock_gettime(CLOCK_REALTIME, &curino->atime);
        curino->mtime = curino->ctime = curino->atime;
        curino->dir.entries = NULL;
        curino->dir.entry_count = 0;
        atomic_init(&curino->refcount, 1);
        atomic_init(&curino->access_count, 0);
        inodecache_add(global_fs, curino);
    }
    return curino;
}

fs_dirent_t* find_dir(fs_inode_t* inode, const char* dirname){
    if(!S_ISDIR(inode->mode)) return NULL;
    if(!inode->dir.entries || !inode->dir.entry_count) return NULL;
    for(fs_dirent_t* cur = inode->dir.entries; cur; cur = cur->next)
        if(!strncmp(cur->name, dirname, MAX_NAME_LEN)) return cur;
    return NULL;
}

int remove_dir(fs_session_t* session, fs_inode_t* dir, const char* name){
    if(!S_ISDIR(dir->mode)) return -ENOTDIR;
    fs_dirent_t* cur = dir->dir.entries;
    fs_dirent_t** prev = &(dir->dir.entries);
    for(; cur; prev = &(cur->next), cur = cur->next){
        if(!strcmp(cur->name, name)){
            *prev = cur->next;
            fs_free(session, cur);
            dir->dir.entry_count--;
            clock_gettime(CLOCK_REALTIME, &dir->mtime);
            dir->ctime = dir->mtime;
            dir->flags |= INODE_DIRTY;
            return 0;
        }
    }
    return -ENOENT;
}

int add_dir(fs_session_t*globalfs,  fs_inode_t* inode, const char* name, fuse_ino_t ino, mode_t mode){
    if(!S_ISDIR(inode->mode)) return -ENOTDIR;
    if(strlen(name) > MAX_NAME_LEN) return -ENAMETOOLONG;
    if(find_dir(inode, name)) return EEXIST;
    fs_dirent_t* newentry = (fs_dirent_t*)malloc( sizeof(fs_dirent_t));//fs_malloc(globalfs, sizeof(fs_dirent_t));
    if(!newentry) return -ENOMEM;
    strcpy(newentry->name, name);
    newentry->ino = ino;
    newentry->type = mode;
    newentry->next = inode->dir.entries;
    inode->dir.entries = newentry;
    inode->dir.entry_count++;
    clock_gettime(CLOCK_REALTIME, &(inode->mtime));
    inode->ctime = inode->mtime;
    inode->flags |= INODE_DIRTY;
    return 0;
}

void my_llfuse_init(__attribute__((unused))void *userdata, struct fuse_conn_info *conn){
    conn->want |= FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE | FUSE_CAP_SPLICE_READ | FUSE_CAP_FLOCK_LOCKS | FUSE_CAP_POSIX_LOCKS 
    | FUSE_CAP_ATOMIC_O_TRUNC | FUSE_CAP_EXPORT_SUPPORT  | FUSE_CAP_DONT_MASK;
    conn->max_write = 1024*1024; 
}

void my_llfuse_destroy(__attribute__((unused)) void* userdata){
    printf("Fuse FS is now destroyed\n");
}

void my_llfuse_getattr (fuse_req_t req, fuse_ino_t ino,
             __attribute__((unused))struct fuse_file_info *fi){
    fs_session_t* global_fs = (fs_session_t*)fuse_req_userdata(req);
    fs_inode_t* res = inodecache_get(global_fs, ino);
    if(!res){
        fuse_reply_err(req, ENOENT);
        return;
    }
    struct stat buf;
    memset(&buf, 0, sizeof(struct stat));
    buf.st_ino = res->ino;
    buf.st_mode = res->mode;
    buf.st_nlink = res->nlink;
    buf.st_uid = res->uid;
    buf.st_gid = res->gid;
    buf.st_size = res->size;
    buf.st_blocks = res->blocks;
    buf.st_atime = res->atime.tv_sec;
    buf.st_mtime = res->mtime.tv_sec;
    buf.st_ctime = res->ctime.tv_sec;
    inode_put(global_fs, res);
    fuse_reply_attr(req, &buf, global_fs->attr_timeout);
}

void my_llfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
             __attribute__((unused))struct fuse_file_info *fi){
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);    
    atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* resino = inodecache_get(globalfs, ino);
    if(!resino){
        fuse_reply_err(req, ENOENT);
        return;
    }
    if(!S_ISDIR(resino->mode)){
        inode_put(globalfs, resino);
        fuse_reply_err(req, ENOTDIR);
        return;
    }    
    char* buf = (char*)malloc(size);
    if(!buf){
        inode_put(globalfs, resino);
        fuse_reply_err(req, ENOMEM);
        return;
    }
    
    size_t curused = 0; 
    off_t curofset = 0;
    struct stat stbuf;    
    if (off <= curofset) {
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = ino;
        stbuf.st_mode = resino->mode;
        stbuf.st_uid = resino->uid;
        stbuf.st_gid = resino->gid;
        stbuf.st_atime = resino->atime.tv_sec;
        stbuf.st_ctime = resino->ctime.tv_sec;
        stbuf.st_mtime = resino->mtime.tv_sec;
        stbuf.st_nlink = resino->nlink;
        stbuf.st_size = resino->size;
        stbuf.st_blocks = resino->blocks;
        
        size_t entry_size = fuse_add_direntry(req, buf + curused, size - curused,
                                            ".", &stbuf, ++curofset);
        if (entry_size <= size - curused) curused += entry_size; 
    } else {
        curofset++;
    }
    if (off <= curofset && curused < size) {
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = (ino == FUSE_ROOT_ID) ? FUSE_ROOT_ID : 1; // Parent inode
        stbuf.st_mode = S_IFDIR | 0755;
        stbuf.st_nlink = 2;
        
        size_t entry_size = fuse_add_direntry(req, buf + curused, size - curused,
                                            "..", &stbuf, ++curofset);
        if (entry_size <= size - curused)
            curused += entry_size;
    } else {
        curofset++;
    }
    
    fs_dirent_t* entry = resino->dir.entries;
    int entry_count = 0;
    while (entry && curused < size) {
        if (off <= curofset) {
            memset(&stbuf, 0, sizeof(stbuf));
            stbuf.st_ino = entry->ino;
            stbuf.st_mode = entry->type;
            size_t entry_size = fuse_add_direntry(req, buf + curused, size - curused,
                                                entry->name, &stbuf, ++curofset);
            if (entry_size <= size - curused) {
                curused += entry_size;
            } else {
                break;
            }
        } else {
            curofset++;
        }
        entry = entry->next;
        entry_count++;
    }
    inode_put(globalfs, resino);
    fuse_reply_buf(req, buf, curused);
    free(buf);
}

void my_llfuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name){    
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(struct fuse_entry_param));
    atomic_fetch_add(&(globalfs->total_requests), 1);
    fs_inode_t* res = inodecache_get(globalfs, parent);
    if (!res) {
        fuse_reply_err(req, ENOENT);
        return;
    }    
    fs_dirent_t* res2 = find_dir(res, name);
    if(!res2){
        inode_put(globalfs, res);
        fuse_reply_err(req, ENOENT);
        return;
    }    
    fs_inode_t* res3 = inodecache_get(globalfs, res2->ino);
    if(!res3){
        inode_put(globalfs, res);
        fuse_reply_err(req, ENOENT);
        return;
    }
    e.ino = res3->ino;
    e.generation = 1;
    e.attr_timeout = globalfs->attr_timeout;
    e.entry_timeout = globalfs->entry_timeout;
    e.attr.st_ino = res3->ino;
    e.attr.st_mode = res3->mode;
    e.attr.st_nlink = res3->nlink;
    e.attr.st_uid = res3->uid;
    e.attr.st_gid = res3->gid;
    e.attr.st_size = res3->size;
    e.attr.st_blocks = res3->blocks;
    e.attr.st_atime = res3->atime.tv_sec;
    e.attr.st_mtime = res3->mtime.tv_sec;
    e.attr.st_ctime = res3->ctime.tv_sec;
    inode_put(globalfs, res);
    fuse_reply_entry(req, &e);
}

static void my_llfuse_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    fuse_reply_err(req, 0);
}

static void my_llfuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t type){
        fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);

    atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* parent_inode = inodecache_get(globalfs, parent);
    if(!parent_inode){
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    if(!S_ISDIR(parent_inode->mode)){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    
    if(find_dir(parent_inode, name)){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, EEXIST);
        return;
    }
    
    fs_inode_t* new_ino =(fs_inode_t*) malloc( sizeof(fs_inode_t)); //fs_malloc(globalfs, sizeof(fs_inode_t));
    if(!new_ino){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, ENOMEM);
        return;
    }
    
    memset(new_ino, 0, sizeof(fs_inode_t));
    fuse_ino_t next_ino = atomic_fetch_add(&(globalfs->next_ino), 1);
    new_ino->dir.entries = NULL;
    new_ino->dir.entry_count = 0;
    new_ino->ino = next_ino;
    new_ino->nlink = 2;
    new_ino->mode = S_IFDIR | (type & 0777); 
    new_ino->uid = fuse_req_ctx(req)->uid;
    new_ino->gid = fuse_req_ctx(req)->gid;
    clock_gettime(CLOCK_REALTIME,&(new_ino->atime));
    new_ino->mtime = new_ino->atime;
    new_ino->ctime = new_ino->atime;
    atomic_init(&(new_ino->refcount), 1);
    atomic_init(&(new_ino->access_count), 0);
    
    int res = add_dir(globalfs,parent_inode, name, new_ino->ino, S_IFDIR);
    if(res){
        inode_put(globalfs, parent_inode);
        fs_free(globalfs, new_ino);
        fuse_reply_err(req, -res);
        return;
    }
    
    parent_inode->nlink++; 
    
    inodecache_add(globalfs, new_ino);

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(struct fuse_entry_param));
    e.ino = new_ino->ino;
    e.generation = 1;
    e.attr_timeout = globalfs->attr_timeout;
    e.entry_timeout = globalfs->entry_timeout;
    e.attr.st_ino = new_ino->ino;
    e.attr.st_atime = new_ino->atime.tv_sec;
    e.attr.st_mtime = new_ino->mtime.tv_sec;
    e.attr.st_ctime = new_ino->ctime.tv_sec;
    e.attr.st_blocks = new_ino->blocks;
    e.attr.st_gid = new_ino->gid;
    e.attr.st_uid = new_ino->uid;
    e.attr.st_mode = new_ino->mode;
    e.attr.st_nlink = new_ino->nlink;
    e.attr.st_size = new_ino->size;
    
    inode_put(globalfs, parent_inode);
    fuse_reply_entry(req, &e);
}

fs_session_t* init_fs(void){
    fs_session_t* global_fs = (fs_session_t*)malloc(sizeof(fs_session_t));
    if(!global_fs) return NULL;
    memset(global_fs, 0, sizeof(fs_session_t));
    
    global_fs->memory_pool = (memory_pool_t*)malloc(sizeof(memory_pool_t));
    if(!global_fs->memory_pool){
        free(global_fs);    
        return NULL;
    }
    if(!set_memory_pool(&global_fs->memory_pool, MEMORY_POOL_SIZE)){
        free(global_fs);
        return NULL;
    }
    
    global_fs->cache = (inode_cache_t*)malloc(sizeof(inode_cache_t));
    if(!global_fs->cache){
        munmap(global_fs->memory_pool->base, global_fs->memory_pool->size);
        free(global_fs->memory_pool);
        free(global_fs);
        return NULL; 
    }
    memset(global_fs->cache->hashtable, 0, sizeof(global_fs->cache->hashtable));
    global_fs->cache->lru_head = (fs_inode_t*)malloc(sizeof(fs_inode_t));
    global_fs->cache->lru_tail = (fs_inode_t*)malloc(sizeof(fs_inode_t));
    
    if(!global_fs->cache->lru_head || !global_fs->cache->lru_tail) {
        if(global_fs->cache->lru_head) free(global_fs->cache->lru_head);
        if(global_fs->cache->lru_tail) free(global_fs->cache->lru_tail);
        munmap(global_fs->memory_pool->base, global_fs->memory_pool->size);
        free(global_fs->memory_pool);
        free(global_fs->cache);
        free(global_fs);
        return NULL;
    }
    memset(global_fs->cache->lru_head, 0, sizeof(fs_inode_t));
    memset(global_fs->cache->lru_tail, 0, sizeof(fs_inode_t));
    global_fs->cache->lru_head->lru_n = global_fs->cache->lru_tail;
    global_fs->cache->lru_head->lru_p = NULL;
    global_fs->cache->lru_tail->lru_p = global_fs->cache->lru_head;
    global_fs->cache->lru_tail->lru_n = NULL;
    global_fs->cache->lru_head->ino = UINT64_MAX;
    global_fs->cache->lru_tail->ino = UINT64_MAX - 1;
    global_fs->cache->lru_head->hash_n = NULL;
    global_fs->cache->lru_tail->hash_n = NULL;
    global_fs->cache->max_cached = MAX_INODES;
    global_fs->cache->cached_count = 0;
    atomic_init(&global_fs->cache->hits, 0);
    atomic_init(&global_fs->cache->misses, 0);
    atomic_init(&global_fs->cache->evictions, 0);
    atomic_init(&global_fs->next_ino, 2);
    atomic_init(&global_fs->total_requests, 0);
    atomic_init(&global_fs->errors, 0);
    atomic_init(&global_fs->cache_hits, 0);
    global_fs->attr_timeout = 1.0;
    global_fs->entry_timeout = 1.0;
    fs_inode_t* root =(fs_inode_t*) malloc( sizeof(fs_inode_t)); //fs_malloc(global_fs, sizeof(fs_inode_t));
    if (!root) {
        // cleanup and return error
    }
    memset(root, 0, sizeof(fs_inode_t));
    root->ino = FUSE_ROOT_ID;
    root->mode = S_IFDIR | 0755;
    root->nlink = 2;
    root->uid = getuid();
    root->gid = getgid();
    clock_gettime(CLOCK_REALTIME, &root->atime);
    root->mtime = root->ctime = root->atime;
    root->dir.entries = NULL;
    root->dir.entry_count = 0;
    atomic_init(&root->refcount, 1);
    atomic_init(&root->access_count, 0);
    inodecache_add(global_fs, root);
    return global_fs;
}


static void my_llfuse_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi){
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);
    atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* res = inodecache_get(globalfs, ino);
    if(!res){
        fuse_reply_err(req, ENOENT);
        return;
    }
    if(!S_ISREG(res->mode)){
        inode_put(globalfs, res);
        fuse_reply_err(req, EISDIR);
        return;
    }
    
    int access_mask = (fi->flags) & O_ACCMODE;
    switch(access_mask){
        case O_RDONLY:
            if(!(res->mode & S_IRUSR)){ 
                inode_put(globalfs, res);
                fuse_reply_err(req, EACCES);
                return;
            } 
            break;
        case O_WRONLY:
            if(!(res->mode & S_IWUSR)){ 
                inode_put(globalfs, res);
                fuse_reply_err(req, EACCES);
                return;
            } 
            break;
        case O_RDWR:
            if(!(res->mode & (S_IWUSR | S_IRUSR))){ 
                inode_put(globalfs, res);
                fuse_reply_err(req, EACCES);
                return;
            } 
            break;
    }
    
    if(fi->flags & O_TRUNC){
        res->size = 0;
        if(res->file.data) {
            fs_free(globalfs, res->file.data);
            res->file.data = NULL;
            res->file.allocated = 0;
            res->file.capacity = 0;
        }
        clock_gettime(CLOCK_REALTIME, &(res->mtime));
        res->ctime = res->mtime;
    }
    
    fi->fh = (uint64_t)((uintptr_t)res);
    atomic_fetch_add(&(res->refcount), 1);
    
    inode_put(globalfs, res);
    fuse_reply_open(req, fi);
}

uint8_t enable_encryption_support(void){
    printf("Enable encryption support for the file? (yes/no) case not sensible!\n");
    char res_command[4];
    fgets(res_command,4,stdin);
    res_command[strcspn(res_command, "\n \t")] = '\n';
    for(size_t chr = 0; chr < strlen(res_command); ++chr)
        if(res_command[chr] >= 65 && res_command[chr] <=90) res_command[chr] -= 32;
    if(!strcmp(res_command, "yes")) return 1;
    return 0;
}

static void my_llfuse_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                         mode_t mode, struct fuse_file_info *fi) {
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);
    
                        atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* parent_inode = inodecache_get(globalfs, parent);
    if(!parent_inode){
        fuse_reply_err(req, ENOENT);
        return;
    }
    if(!S_ISDIR(parent_inode->mode)){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    
    if(find_dir(parent_inode, name)){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, EEXIST);
        return;
    }
    
    fs_inode_t* new_inode =(fs_inode_t*) malloc( sizeof(fs_inode_t));//fs_malloc(globalfs, sizeof(fs_inode_t));
    if(!new_inode){
        inode_put(globalfs, parent_inode);
        fuse_reply_err(req, ENOMEM);
        return;
    }
    uint8_t is_enc = enable_encryption_support(); 
    if(is_enc) printf("Encryption support enabled!\n");
    is_enc = 1;
    memset(new_inode, 0, sizeof(fs_inode_t));
    fuse_ino_t next_ino = atomic_fetch_add(&(globalfs->next_ino), 1);
    new_inode->ino = next_ino;
    new_inode->mode = S_IFREG | (mode & 0777);
    new_inode->nlink = 1;
    new_inode->uid = fuse_req_ctx(req)->uid;
    new_inode->gid = fuse_req_ctx(req)->gid;
    new_inode->size = 0;
    new_inode->blocks = 0;
    clock_gettime(CLOCK_REALTIME, &new_inode->atime);
    new_inode->mtime = new_inode->ctime = new_inode->atime;
    new_inode->file.data = NULL;
    new_inode->file.allocated = 0;
    new_inode->file.capacity = 0;
    new_inode->file.is_encrypted = is_enc;
    atomic_init(&new_inode->refcount, 2);
    atomic_init(&new_inode->access_count, 0);
    
    int res = add_dir(globalfs,parent_inode, name, new_inode->ino, S_IFREG);
    if(res){
        inode_put(globalfs, parent_inode);
        fs_free(globalfs, new_inode);
        fuse_reply_err(req, -res);
        return;
    }
    
    inodecache_add(globalfs, new_inode);
    
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(struct fuse_entry_param));
    e.ino = new_inode->ino;
    e.generation = 1;
    e.attr_timeout = globalfs->attr_timeout;
    e.entry_timeout = globalfs->entry_timeout;
    e.attr.st_ino = new_inode->ino;
    e.attr.st_mode = new_inode->mode;
    e.attr.st_nlink = new_inode->nlink;
    e.attr.st_uid = new_inode->uid;
    e.attr.st_gid = new_inode->gid;
    e.attr.st_size = new_inode->size;
    e.attr.st_blocks = new_inode->blocks;
    e.attr.st_atime = new_inode->atime.tv_sec;
    e.attr.st_mtime = new_inode->mtime.tv_sec;
    e.attr.st_ctime = new_inode->ctime.tv_sec;
    
    fi->fh = (uint64_t)((uintptr_t)new_inode);
    
    inode_put(globalfs, parent_inode);
    fuse_reply_create(req, &e, fi);
    if(is_enc) printf("Encryption support enabled!\n");
}

static char* decrypt_file_to_buffer(fs_inode_t* inode, size_t* decrypted_size) {
    printf("AICIIIIIIIIIIIIIIIIIIII\n");
    if (!inode->file.is_encrypted || !inode->file.data || inode->file.allocated == 0) {
        *decrypted_size = 0;
        return NULL;
    }
    printf("**************************************\n");
    char tmp_path[MAX_NAME_LEN];
    snprintf(tmp_path, MAX_NAME_LEN, "/dev/shm/fuse_%d_%llu_decrypt.tmp", 
             getpid(), (unsigned long long)inode->ino);
    
    FILE *tmp = fopen(tmp_path, "w+b");
    if (!tmp) return NULL;
    fchmod(fileno(tmp), 0600);
    if (fwrite(inode->file.data, 1, inode->file.allocated, tmp) != inode->file.allocated) {
        fclose(tmp);
        unlink(tmp_path);
        return NULL;
    }
    fflush(tmp);
    fclose(tmp);
    
    char command[MAX_NAME_LEN];
    snprintf(command, MAX_NAME_LEN, 
             "python3 /home/razvan/projejct/securefs/encrypt.py decrypt %llu %s",
             (unsigned long long)inode->ino, tmp_path);
    
    if (system(command) != 0) {
        unlink(tmp_path);
        return NULL;
    }
    tmp = fopen(tmp_path, "rb");
    if (!tmp) {
        unlink(tmp_path);
        return NULL;
    }
    
    fseek(tmp, 0, SEEK_END);
    long size = ftell(tmp);
    rewind(tmp);
    
    if (size <= 0) {
        fclose(tmp);
        unlink(tmp_path);
        return NULL;
    }
    
    char* buffer = malloc(size);
    if (!buffer || fread(buffer, 1, size, tmp) != (size_t)size) {
        fclose(tmp);
        unlink(tmp_path);
        free(buffer);
        return NULL;
    }
    
    fclose(tmp);
    unlink(tmp_path);
    
    *decrypted_size = size;
    return buffer;
}

static int encrypt_and_store_buffer(fs_inode_t* inode, const char* plaintext, size_t plaintext_size) {
    char tmp_path[MAX_NAME_LEN];
    snprintf(tmp_path, MAX_NAME_LEN, "/dev/shm/fuse_%d_%llu_encrypt.tmp", 
             getpid(), (unsigned long long)inode->ino);
    
    FILE *tmp = fopen(tmp_path, "w+b");
    if (!tmp) return -1;
    fchmod(fileno(tmp), 0600);
    printf("BBBBBBBBBBBBBBBBBBB\n");
    
    if (fwrite(plaintext, 1, plaintext_size, tmp) != plaintext_size) {
        fclose(tmp);
        unlink(tmp_path);
        return -1;
    }
    fflush(tmp);
    fclose(tmp);
    char command[MAX_NAME_LEN];
    printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    snprintf(command, MAX_NAME_LEN, 
             "python3 /home/razvan/projejct/securefs/encrypt.py encrypt %llu %s",
             (unsigned long long)inode->ino, tmp_path);
    
    if (system(command) != 0) {
        unlink(tmp_path);
        return -1;
    }
    tmp = fopen(tmp_path, "rb");
    if (!tmp) {
        unlink(tmp_path);
        return -1;
    }
    
    fseek(tmp, 0, SEEK_END);
    long encrypted_size = ftell(tmp);
    rewind(tmp);
    
    if (encrypted_size <= 0) {
        fclose(tmp);
        unlink(tmp_path);
        return -1;
    }
    if ((size_t)encrypted_size > inode->file.capacity) {
        size_t new_capacity = ((encrypted_size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        void* new_data = malloc(new_capacity);
        if (!new_data) {
            fclose(tmp);
            unlink(tmp_path);
            return -1;
        }
        
        if (inode->file.data) {
            explicit_bzero(inode->file.data, inode->file.capacity);
            free(inode->file.data);
        }
        
        inode->file.data = new_data;
        inode->file.capacity = new_capacity;
    }
    if (fread(inode->file.data, 1, encrypted_size, tmp) != (size_t)encrypted_size) {
        fclose(tmp);
        unlink(tmp_path);
        return -1;
    }
    
    fclose(tmp);
    unlink(tmp_path);
    inode->file.allocated = encrypted_size;
    inode->size = plaintext_size;
    return 0;
}

static void my_llfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size,
                       off_t off, struct fuse_file_info *fi) {
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);
    atomic_fetch_add(&(globalfs->total_requests), 1);
    printf("HELOOOOOOOOOOOOOOOOOOOOOOOOOOOOO\n");
    
    fs_inode_t* inode = (fs_inode_t*)((uintptr_t)fi->fh);
    if(!inode || inode->ino != ino) {
        fuse_reply_err(req, EBADF);
        return;
    }
    
    if(!S_ISREG(inode->mode)) {
        fuse_reply_err(req, EISDIR);
        return;
    }
        if(off >= inode->size) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    
    if(off + size > inode->size) {
        size = inode->size - off;
    }
    
    if(size == 0) {
        fuse_reply_buf(req, NULL, 0);
        return;
    }
    
    clock_gettime(CLOCK_REALTIME, &inode->atime);
    printf("***JDGJHGDHGHDGHDGHD\n");
    
    if (inode->file.is_encrypted) {
        size_t decrypted_size;
        char* decrypted_buffer = decrypt_file_to_buffer(inode, &decrypted_size);
        
        if (!decrypted_buffer || decrypted_size < off + size) {
            if (decrypted_buffer) {
                explicit_bzero(decrypted_buffer, decrypted_size);
                free(decrypted_buffer);
            }
            fuse_reply_err(req, EIO);
            return;
        }
        char* response_buffer = malloc(size);
        if (!response_buffer) {
            explicit_bzero(decrypted_buffer, decrypted_size);
            free(decrypted_buffer);
            fuse_reply_err(req, ENOMEM);
            return;
        }
        memcpy(response_buffer, decrypted_buffer + off, size);
        explicit_bzero(decrypted_buffer, decrypted_size);
        free(decrypted_buffer);
        fuse_reply_buf(req, response_buffer, size);
        explicit_bzero(response_buffer, size);
        free(response_buffer);
        
    } else {
        if (!inode->file.data) {
            fuse_reply_buf(req, NULL, 0);
            return;
        }
        fuse_reply_buf(req, (char*)inode->file.data + off, size);
    }
}

static void my_llfuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                        size_t size, off_t off, struct fuse_file_info *fi) {
    fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);
    atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* inode = (fs_inode_t*)((uintptr_t)fi->fh);
    if(!inode || inode->ino != ino) {
        fuse_reply_err(req, EBADF);
        return;
    }
    
    if(!S_ISREG(inode->mode)) {
        fuse_reply_err(req, EISDIR);
        return;
    }
    if (inode->file.is_encrypted) {
        size_t decrypted_size = 0;
        char* decrypted_buffer = NULL;
        if (inode->file.data && inode->file.allocated > 0) {
            decrypted_buffer = decrypt_file_to_buffer(inode, &decrypted_size);
            if (!decrypted_buffer) {
                fuse_reply_err(req, EIO);
                return;
            }
        }
        printf("CCCCCCCCCCCCCCCCCCCCCC\n");
        size_t new_size = (off + size > decrypted_size)? off+ size :decrypted_size;
        char* new_buffer = calloc(1, new_size);
        if (!new_buffer) {
            if (decrypted_buffer) {
                explicit_bzero(decrypted_buffer, decrypted_size);
                free(decrypted_buffer);
            }
            fuse_reply_err(req, ENOMEM);
            return;
        }
        if (decrypted_buffer && decrypted_size > 0) {
            memcpy(new_buffer, decrypted_buffer, decrypted_size);
            explicit_bzero(decrypted_buffer, decrypted_size);
            free(decrypted_buffer);
        }
        memcpy(new_buffer + off, buf, size);
        if (encrypt_and_store_buffer(inode, new_buffer, new_size) != 0) {
            explicit_bzero(new_buffer, new_size);
            free(new_buffer);
            fuse_reply_err(req, EIO);
            return;
        }
        
        explicit_bzero(new_buffer, new_size);
        free(new_buffer);
        
    } else {
        size_t needed_size = off + size;
        
        if(needed_size > inode->file.capacity) {
            size_t new_capacity = ((needed_size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
            void* new_data = malloc(new_capacity);
            if(!new_data) {
                fuse_reply_err(req, ENOMEM);
                return;
            }
            
            if(inode->file.data && inode->size > 0) {
                memcpy(new_data, inode->file.data, inode->size);
                free(inode->file.data);
            }
            
            inode->file.data = new_data;
            inode->file.capacity = new_capacity;
        }
        
        memcpy((char*)inode->file.data + off, buf, size);
        
        if(off + size > inode->size) {
            inode->size = off + size;
            inode->file.allocated = inode->size;  //fr non-encrypted these are  same
        }
    }
    
    clock_gettime(CLOCK_REALTIME, &inode->mtime);
    inode->ctime = inode->mtime;
    inode->flags |= INODE_DIRTY;
    inode->blocks = (inode->size + 511) / 512;
    
    fuse_reply_write(req, size);
}

static void my_llfuse_write1(fuse_req_t req, fuse_ino_t ino, const char *buf,
                        size_t size, off_t off, struct fuse_file_info *fi) {
        fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);

                            atomic_fetch_add(&(globalfs->total_requests), 1);
    
    fs_inode_t* inode = (fs_inode_t*)((uintptr_t)fi->fh);
    if(!inode || inode->ino != ino) {
        fuse_reply_err(req, EBADF);
        return;
    }
    
    if(!S_ISREG(inode->mode)) {
        fuse_reply_err(req, EISDIR);
        return;
    }
    
    size_t needed_size = off + size;
    
    if(needed_size > inode->file.capacity) {
        size_t new_capacity = ((needed_size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        void* new_data = malloc( new_capacity);//fs_malloc(globalfs, new_capacity);
        if(!new_data) {
            fuse_reply_err(req, ENOMEM);
            return;
        }
        
        if(inode->file.data && inode->size > 0) {
            memcpy(new_data, inode->file.data, inode->size);
            free(inode->file.data);
        }
        
        inode->file.data = new_data;
        inode->file.capacity = new_capacity;
    }


    char tmp_path[MAX_NAME_LEN];
    snprintf(tmp_path, MAX_NAME_LEN, "/dev/shm/fuse_%d_%llu.tmp",  getpid(), (unsigned long long)ino);
    FILE *tmp = fopen(tmp_path, "w+b");
    if (!tmp) {
        fuse_reply_err(req, EIO);
        return;
    }
    fchmod(fileno(tmp), 0600);

    if (fwrite(buf, 1, size, tmp) != size) {
        fclose(tmp);
        unlink(tmp_path);
        fuse_reply_err(req, EIO);
        return;
    }
    fflush(tmp); 
    char command[MAX_NAME_LEN];
    snprintf(command, MAX_NAME_LEN, "python3 /home/razvan/projejct/securefs/encrypt.py encrypt %llu %s",(unsigned long long)ino, tmp_path);
    int ret = system(command);
    if (ret != 0) {
        unlink(tmp_path);
        fuse_reply_err(req, EIO);
        return;
    }
    rewind(tmp);
    char *buffer = (char*)malloc((size + 200) * sizeof(char));
    if(!buffer){
        unlink(tmp_path);
        fuse_reply_err(req, ENOMEM);
        return;
    }
    size_t read_bytes = fread(buffer, 1, size + 200, tmp);
    fclose(tmp);
    unlink(tmp_path);

    if (read_bytes != size) {
        free(buffer);
        fuse_reply_err(req, EIO);
        return;
    }
    
    memcpy((char*)inode->file.data + off, buffer, size + 200);

    explicit_bzero(buffer, size + 200);  //Wipe decrypted data from memory
    free(buffer);
    
    
    if(needed_size > inode->size) {
        inode->size = needed_size;
        inode->blocks = (inode->size + 511) / 512;
    }
    
    clock_gettime(CLOCK_REALTIME, &inode->mtime);
    inode->ctime = inode->mtime;
    inode->flags |= INODE_DIRTY;
    
    fuse_reply_write(req, size);
}

static void my_llfuse_release(fuse_req_t req,
    fuse_ino_t ino, struct fuse_file_info *fi) {
        fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);

        printf("[DEBUG] release called on ino=%lu\n", ino);
    fs_inode_t* inode = (fs_inode_t*)((uintptr_t)fi->fh);
    if (inode && inode->ino == ino) {
        inode_put(globalfs, inode);
    } else {
        printf("[WARNING] release: invalid fh or ino mismatch\n");
    }
    fuse_reply_err(req, 0);
}


static void my_llfuse_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    fuse_reply_err(req, 0);
}


static void my_llfuse_setattr(fuse_req_t req, fuse_ino_t ino,
                          struct stat *attr, int to_set,
                          struct fuse_file_info *fi) {
    
        fs_session_t* globalfs = (fs_session_t*)fuse_req_userdata(req);

                            fs_inode_t* inode = inodecache_get(globalfs, ino);
    if (!inode) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (to_set & FUSE_SET_ATTR_MODE) {
        inode->mode = (inode->mode & S_IFMT) | (attr->st_mode & 07777);
    }
    if (to_set & FUSE_SET_ATTR_UID) {
        inode->uid = attr->st_uid;
    }
    if (to_set & FUSE_SET_ATTR_GID) {
        inode->gid = attr->st_gid;
    }
    if (to_set & FUSE_SET_ATTR_SIZE) {

    }
    if (to_set & FUSE_SET_ATTR_ATIME) {
        inode->atime.tv_sec = attr->st_atime;
        inode->atime.tv_nsec = attr->st_atime;
    }
    if (to_set & FUSE_SET_ATTR_MTIME) {
        inode->mtime.tv_sec = attr->st_mtime;
        inode->mtime.tv_nsec = attr->st_mtime;
    }

    clock_gettime(CLOCK_REALTIME, &inode->ctime);
    
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = inode->ino;
    stbuf.st_mode = inode->mode;
    stbuf.st_nlink = inode->nlink;
    stbuf.st_uid = inode->uid;
    stbuf.st_gid = inode->gid;
    stbuf.st_size = inode->size;
    stbuf.st_blocks = inode->blocks;
    stbuf.st_atime = inode->atime.tv_sec;
    stbuf.st_mtime = inode->mtime.tv_sec;
    stbuf.st_ctime = inode->ctime.tv_sec;

    inode_put(globalfs, inode);
    fuse_reply_attr(req, &stbuf, globalfs->attr_timeout);
}

static const struct fuse_lowlevel_ops my_operations = {
    .init = my_llfuse_init,
    .destroy = my_llfuse_destroy,
    .readdir = my_llfuse_readdir,
    .mkdir = my_llfuse_mkdir,
    .getattr = my_llfuse_getattr,
    .open = my_llfuse_open,
    .access = my_llfuse_access,
    .release = my_llfuse_release,
    .read = my_llfuse_read,
    .write = my_llfuse_write,
    .flush = my_llfuse_flush,
    .create = my_llfuse_create,
    .setattr = my_llfuse_setattr,
    .lookup = my_llfuse_lookup
};

int main(int argc, char* argv[]) {
    int return_value = 0;
    struct fuse_args args= FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    if(fuse_parse_cmdline(&args, &opts)) return_value = 1;
    if(opts.show_help){
        fuse_cmdline_help();
//        cleanup_filesystem();
        return_value = 0;
        return 0;
    }
    if(opts.show_version){
        fuse_lowlevel_version();
//        cleanup_filesystem();
        return_value = 0;
        return 0;
    }
    if(!opts.mountpoint){
//        cleanup_filesystem();
        return_value = 1;
        return 1;
    }
    fs_session_t* global_fs = init_fs();
    if(opts.debug) printf("%s", DEBUG_MESS_ACTIVE);
    struct fuse_session* session = fuse_session_new(&args, &my_operations, sizeof(my_operations), global_fs);
    if(!session){
//        cleanup_filesystem();
        fuse_opt_free_args(&args);
        return_value = 1;
        return 1;
    }
    global_fs->fuse_se = session;
    if(fuse_set_signal_handlers(session)){
        return_value = 1;
        cleanup_session(session, &opts, &args, return_value);
        return 1;
    }
    if(fuse_session_mount(session, opts.mountpoint)){
        return_value = 1;
        remove_handlers(session, &opts, &args, return_value);
        return 1;
    }
    fuse_session_loop(session);
    return 0;
}