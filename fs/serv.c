/*
 * File system server main loop -
 * serves IPC requests from other environments.
 */

#include "serv.h"
#include <fd.h>
#include <fsreq.h>
#include <lib.h>
#include <mmu.h>
/*
 * Fields
 * o_file: mapped descriptor for open file
 * o_fileid: file id
 * o_mode: open mode
 * o_ff: va of filefd page
 */
struct Open {
	struct File *o_file;
	u_int o_fileid;
	int o_mode;
	struct Filefd *o_ff;
};

static int encrypt_key_set = 0;
static unsigned char encrypt_key[BLOCK_SIZE];
/*
 * Max number of open files in the file system at once
 */
#define MAXOPEN 1024

#define FILEVA 0x60000000

/*
 * Open file table, a per-environment array of open files
 */
struct Open opentab[MAXOPEN];

/*
 * Virtual address at which to receive page mappings containing client requests.
 */
#define REQVA 0x0ffff000

/*
 * Overview:
 *  Set up open file table and connect it with the file cache.
 */
void serve_init(void) {
	int i;
	u_int va;

	// Set virtual address to map.
	va = FILEVA;

	// Initial array opentab.
	for (i = 0; i < MAXOPEN; i++) {
		opentab[i].o_fileid = i;
		opentab[i].o_ff = (struct Filefd *)va;
		va += BLOCK_SIZE;
	}
}

/*
 * Overview:
 *  Allocate an open file.
 * Parameters:
 *  o: the pointer to the allocated open descriptor.
 * Return:
 * 0 on success, - E_MAX_OPEN on error
 */
int open_alloc(struct Open **o) {
	int i, r;

	// Find an available open-file table entry
	for (i = 0; i < MAXOPEN; i++) {
		switch (pageref(opentab[i].o_ff)) {
		case 0:
			if ((r = syscall_mem_alloc(0, opentab[i].o_ff, PTE_D | PTE_LIBRARY)) < 0) {
				return r;
			}
		case 1:
			*o = &opentab[i];
			memset((void *)opentab[i].o_ff, 0, BLOCK_SIZE);
			return (*o)->o_fileid;
		}
	}

	return -E_MAX_OPEN;
}

// Overview:
//  Look up an open file for envid.
/*
 * Overview:
 *  Look up an open file by using envid and fileid. If found,
 *  the `po` pointer will be pointed to the open file.
 * Parameters:
 *  envid: the id of the request process.
 *  fileid: the id of the file.
 *  po: the pointer to the open file.
 * Return:
 * 0 on success, -E_INVAL on error (fileid illegal or file not open by envid)
 *
 */
int open_lookup(u_int envid, u_int fileid, struct Open **po) {
	struct Open *o;

	if (fileid >= MAXOPEN) {
		return -E_INVAL;
	}

	o = &opentab[fileid];

	if (pageref(o->o_ff) <= 1) {
		return -E_INVAL;
	}

	*po = o;
	return 0;
}
/*
 * Functions with the prefix "serve_" are those who
 * conduct the file system requests from clients.
 * The file system receives the requests by function
 * `ipc_recv`, when the requests are received, the
 * file system will call the corresponding `serve_`
 * and return the result to the caller by function
 * `ipc_send`.
 */

/*
 * Overview:
 * Serve to open a file specified by the path in `rq`.
 * It will try to alloc an open descriptor, open the file
 * and then save the info in the File descriptor. If everything
 * is done, it will use the ipc_send to return the FileFd page
 * to the caller.
 * Parameters:
 * envid: the id of the request process.
 * rq: the request, which contains the path and the open mode.
 * Return:
 * if Success, return the FileFd page to the caller by ipc_send,
 * Otherwise, use ipc_send to return the error value to the caller.
 */
void serve_open(u_int envid, struct Fsreq_open *rq) {
	struct File *f;
	struct Filefd *ff;
	int r;
	struct Open *o;

	// Find a file id.
	if ((r = open_alloc(&o)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	if ((rq->req_omode & O_CREAT) && (r = file_create(rq->req_path, &f)) < 0 &&
	    r != -E_FILE_EXISTS) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	// Open the file.
	if ((r = file_open(rq->req_path, &f)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	// Save the file pointer.
	o->o_file = f;

	// If mode include O_TRUNC, set the file size to 0
	if (rq->req_omode & O_TRUNC) {
		if ((r = file_set_size(f, 0)) < 0) {
			ipc_send(envid, r, 0, 0);
		}
	}

	// Fill out the Filefd structure
	ff = (struct Filefd *)o->o_ff;
	ff->f_file = *f;
	ff->f_fileid = o->o_fileid;
	o->o_mode = rq->req_omode;
	ff->f_fd.fd_omode = o->o_mode;
	ff->f_fd.fd_dev_id = devfile.dev_id;
	ipc_send(envid, 0, o->o_ff, PTE_D | PTE_LIBRARY);
}

/*
 * Overview:
 *  Serve to map the file specified by the fileid in `rq`.
 *  It will use the fileid and envid to find the open file and
 *  then call the `file_get_block` to get the block and use
 *  the `ipc_send` to return the block to the caller.
 * Parameters:
 *  envid: the id of the request process.
 *  rq: the request, which contains the fileid and the offset.
 * Return:
 *  if Success, use ipc_send to return zero and  the block to
 *  the caller.Otherwise, return the error value to the caller.
 */
void serve_map(u_int envid, struct Fsreq_map *rq) {
	struct Open *pOpen;
	u_int filebno;
	void *blk;
	int r;

	if ((r = open_lookup(envid, rq->req_fileid, &pOpen)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	int flag = 1;
	filebno = rq->req_offset / BLOCK_SIZE;
	if (pOpen->o_mode == O_ENCRYPT) {
		if (encrypt_key_set != 1) {
			ipc_send(envid, -E_BAD_KEY, 0, 0);
			flag = 0;
		}
	}
	if ((r = file_get_block(pOpen->o_file, filebno, &blk)) < 0) {
		if (flag) ipc_send(envid, r, 0, 0);
		return;
	}

	ipc_send(envid, 0, blk, PTE_D | PTE_LIBRARY);
}

/*
 * Overview:
 *  Serve to set the size of a file specified by the fileid in `rq`.
 *  It tries to find the open file by using open_lookup function and then
 *  call the `file_set_size` to set the size of the file.
 * Parameters:
 *  envid: the id of the request process.
 *  rq: the request, which contains the fileid and the size.
 * Return:
 * if Success, use ipc_send to return 0 to the caller. Otherwise,
 * return the error value to the caller.
 */
void serve_set_size(u_int envid, struct Fsreq_set_size *rq) {
	struct Open *pOpen;
	int r;
	if ((r = open_lookup(envid, rq->req_fileid, &pOpen)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	if ((r = file_set_size(pOpen->o_file, rq->req_size)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	ipc_send(envid, 0, 0, 0);
}

/*
 * Overview:
 *  Serve to close a file specified by the fileid in `rq`.
 *  It will use the fileid and envid to find the open file and
 * 	then call the `file_close` to close the file.
 * Parameters:
 *  envid: the id of the request process.
 * 	rq: the request, which contains the fileid.
 * Return:
 *  if Success, use ipc_send to return 0 to the caller.Otherwise,
 *  return the error value to the caller.
 */
void serve_close(u_int envid, struct Fsreq_close *rq) {
	struct Open *pOpen;

	int r;

	if ((r = open_lookup(envid, rq->req_fileid, &pOpen)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}
	int flag = 1;	
	if (pOpen->o_mode == O_ENCRYPT) {
		if (encrypt_key_set != 1) {
			ipc_send(envid, -E_BAD_KEY, 0, 0);
			flag = 0;
		}
	}
	if (flag) file_close(pOpen->o_file);
	ipc_send(envid, 0, 0, 0);
}

/*
 * Overview:
 *  Serve to remove a file specified by the path in `req`.
 *  It calls the `file_remove` to remove the file and then use
 *  the `ipc_send` to return the result to the caller.
 * Parameters:
 *  envid: the id of the request process.
 *  rq: the request, which contains the path.
 * Return:
 *  the result of the file_remove to the caller by ipc_send.
 */
void serve_remove(u_int envid, struct Fsreq_remove *rq) {
	// Step 1: Remove the file specified in 'rq' using 'file_remove' and store its return value.
	int r;
	/* Exercise 5.11: Your code here. (1/2) */
	r = file_remove(rq->req_path);

	// Step 2: Respond the return value to the caller 'envid' using 'ipc_send'.
	/* Exercise 5.11: Your code here. (2/2) */
	ipc_send(envid, r, 0, 0);
}

/*
 * Overview:
 *  Serve to dirty the file.
 *  It will use the fileid and envid to find the open file and
 * 	then call the `file_dirty` to dirty the file.
 * Parameters:
 *  envid: the id of the request process.
 *  rq: the request, which contains the fileid and the offset.
 * `Return`:
 *  if Success, use ipc_send to return 0 to the caller. Otherwise,
 *  return the error value to the caller.
 */
void serve_dirty(u_int envid, struct Fsreq_dirty *rq) {
	struct Open *pOpen;
	int r;

	if ((r = open_lookup(envid, rq->req_fileid, &pOpen)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	if ((r = file_dirty(pOpen->o_file, rq->req_offset)) < 0) {
		ipc_send(envid, r, 0, 0);
		return;
	}

	ipc_send(envid, 0, 0, 0);
}

/*
 * Overview:
 *  Serve to sync the file system.
 *  it calls the `fs_sync` to sync the file system.
 *  and then use the `ipc_send` and `return` 0 to tell the caller
 *  file system is synced.
 */
void serve_sync(u_int envid) {
	fs_sync();
	ipc_send(envid, 0, 0, 0);
}

/*
 * The serve function table
 * File system use this table and the request number to
 * call the corresponding serve function.
 */


void serve_key_set(u_int envid, struct Fsreq_key_set *rq) {
  // 判断当前状态是否已加载密钥，如果已加载密钥， IPC 返回 -E_BAD_KEY
	if (encrypt_key_set == 1) {
		ipc_send(envid, -E_BAD_KEY, 0, 0);
	}

  // 利用 open_lookup 找到对应的 Open 结构体，判断文件大小是否至少有两个磁盘块大小
	struct Open *po;
	int r = open_lookup(envid, rq->req_fileid, &po);
	if (r != 0) ipc_send(envid, -E_INVALID_KEY_FILE,0,0);
	if (po->o_file->f_size < 2 * 4096) ipc_send(envid, -E_INVALID_KEY_FILE, 0, 0);

  // 利用 file_get_block 读取文件的第一个磁盘块，判断第一个字是否为 FS_MAGIC
  	void *va = 0;
	file_get_block(po->o_file, 0, &va);
	if (*((uint32_t *)va) != FS_MAGIC) ipc_send(envid, -E_INVALID_KEY_FILE, 0, 0);

  // 如果密钥文件不合法， IPC 返回 -E_INVALID_KEY_FILE

  // 利用 file_get_block 读取文件的第二个磁盘块，将密钥复制到 encrypt_key 中
	void *va2 = 0;
	file_get_block(po->o_file, 1, &va2);
	int i;
	for (i = 0; i < BLOCK_SIZE; i++) {
		encrypt_key[i] = *((char*)(va2 + i));
	}

  // 将当前状态标记为已加载密钥
	encrypt_key_set = 1;

  // IPC 返回 0
	ipc_send(envid, 0, 0, 0);
}

void serve_key_unset(u_int envid) {
  // 判断当前状态是否已加载密钥，如果未加载密钥， IPC 返回 -E_BAD_KEY
	if (encrypt_key_set == 0) ipc_send(envid, -E_BAD_KEY, 0, 0);

  // 将当前状态标记为未加载密钥
	encrypt_key_set = 0;

  // 将密钥缓存 encrypt_key 清零
	int i;
	for (i=0;i<BLOCK_SIZE;i++) {
		encrypt_key[i] = 0;
	}
  // IPC 返回 0
	ipc_send(envid, 0, 0, 0);
}

void serve_key_isset(u_int envid) {
  // IPC 返回当前状态
	ipc_send(envid, encrypt_key_set, 0, 0);
}

void *serve_table[MAX_FSREQNO] = {
    [FSREQ_OPEN] = serve_open,	 [FSREQ_MAP] = serve_map,     [FSREQ_SET_SIZE] = serve_set_size,
    [FSREQ_CLOSE] = serve_close, [FSREQ_DIRTY] = serve_dirty, [FSREQ_REMOVE] = serve_remove,
    [FSREQ_SYNC] = serve_sync, [FSREQ_KEY_SET] = serve_key_set, [FSREQ_KEY_UNSET] = serve_key_unset, 
    [FSREQ_KEY_ISSET] = serve_key_isset,
};

/*
 * Overview:
 *  The main loop of the file system server.
 *  It receives requests from other processes, if no request,
 *  the kernel will schedule other processes. Otherwise, it will
 *  call the corresponding serve function with the reqeust number
 *  to handle the request.
 */
void serve(void) {
	u_int req, whom, perm;
	void (*func)(u_int, u_int);

	for (;;) {
		perm = 0;

		req = ipc_recv(&whom, (void *)REQVA, &perm);

		// All requests must contain an argument page
		if (!(perm & PTE_V)) {
			debugf("Invalid request from %08x: no argument page\n", whom);
			continue; // just leave it hanging, waiting for the next request.
		}

		// The request number must be valid.
		if (req < 0 || req >= MAX_FSREQNO) {
			debugf("Invalid request code %d from %08x\n", req, whom);
			panic_on(syscall_mem_unmap(0, (void *)REQVA));
			continue;
		}

		// Select the serve function and call it.
		func = serve_table[req];
		func(whom, REQVA);

		// Unmap the argument page.
		panic_on(syscall_mem_unmap(0, (void *)REQVA));
	}
}

/*
 * Overview:
 *  The main function of the file system server.
 *  It will call the `serve_init` to initialize the file system
 *  and then call the `serve` to handle the requests.
 */
int main() {
	user_assert(sizeof(struct File) == FILE_STRUCT_SIZE);

	debugf("FS is running\n");

	serve_init();
	fs_init();

	serve();
	return 0;
}
