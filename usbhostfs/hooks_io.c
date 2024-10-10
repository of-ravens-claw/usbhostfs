//
// Created by cpasjuste on 10/07/17.
//

#include "hooks_io.h"
#include "host_driver.h"

#include <taihen.h>

static SceClass p2sIoClass;
static int host_fds[MAX_HOST_FD];

int module_get_export_func(SceUID pid, const char *modname, uint32_t libnid, uint32_t funcnid, uintptr_t *func);
SceUID (*sceGUIDKernelCreateWithOpt)(SceClass *sce_class, const char *name, SceGUIDKernelCreateOpt *opt, SceObjectBase **obj);

// TODO: Hooking SceIofilemgr functions is a really bad approach.
// We should use vfs instead, just like Deci4p does.

// kernel hooks
static Hook hooks[HOOK_END] =
{
    // io/fcntl.h
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x75192972, _ksceIoOpen        },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0xC3D34965, _ksceIoOpenForPid  },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0xF99DD8A3, _ksceIoClose       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0xE17EFC03, _ksceIoRead        },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x21EE91F0, _ksceIoWrite       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x62090481, _ksceIoLseek       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x0D7BB3E1, _ksceIoRemove      },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0xDC0C4997, _ksceIoRename      },
    // io/fcntl.h
    // io/dirent.h
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x463B25CC, _ksceIoDopen       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x20CF5FC7, _ksceIoDread       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x19C81DD6, _ksceIoDclose      },
    // io/dirent.h
    // io/stat.h
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x7F710B25, _ksceIoMkdir       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x1CC9C634, _ksceIoRmdir       },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x75C96D25, _ksceIoGetstat     },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x462F059B, _ksceIoGetstatByFd },
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x7D42B8DC, _ksceIoChstat      },
    // io/stat.h
    // io/devctl.h
    { -1, 0, "SceIofilemgr", 0x40FD29C7, 0x16882FC4, _ksceIoDevctl      },
    // io/devctl.h
};

static int open_host_fd(const char *file, int flags, SceMode mode)
{
    int uid = -1;

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] < 0)
        {
            uid = io_open((char *) file, flags, mode);
            host_fds[i] = uid;
            break;
        }
    }
    return uid;
}

static int open_host_dfd(const char *dir)
{
    int uid = -1;

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] < 0)
        {
            uid = io_dopen(dir);
            host_fds[i] = uid;
            break;
        }
    }
    return uid;
}

static int close_host_fd(int fd)
{
    int res = -1;

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] == fd)
        {
            res = io_close(fd);
            host_fds[i] = -1;
            break;
        }
    }
    return res;
}

static int close_host_dfd(int fd)
{
    int res = -1;

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] == fd)
        {
            res = io_dclose(fd);
            host_fds[i] = -1;
            break;
        }
    }
    return res;
}

static SceBool is_host_fd(int fd)
{
    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] == fd)
            return SCE_TRUE;
    }
    return SCE_FALSE;
}

SceUID _ksceIoOpen(const char *file, int flags, SceMode mode)
{
    int fid, ret;
    fopen_fd *ffd;

    if (strncmp(file, "host0", 5) != 0)
        return TAI_CONTINUE(SceUID, hooks[HOOK_IO_KOPEN].ref, file, flags, mode);

    if (sceGUIDKernelCreateWithOpt == NULL)
    {
        debugf("_ksceIoOpen: sceGUIDKernelCreateWithOpt function pointer is NULL! Aborting...\n");
        return 0xDEADC0DE;
    }

    fid = open_host_fd(file, flags, mode);
    ret = (*sceGUIDKernelCreateWithOpt)(&p2sIoClass, "io_hook", NULL, (SceObjectBase **) &ffd);
    if (ret < 0)
    {
        debugf("_ksceIoOpen: sceGUIDKernelCreateWithOpt failed (0x%08X)\n", ret);
        return ret;
    }

    ffd->fd = fid;
    ffd->uid = ret;
    debugf("_ksceIoOpen(%s, 0x%08X, 0x%08X): fid = %i, uid = 0x%08X\n", file, flags, mode, ffd->fd, ffd->uid);
    return ret;
}

SceUID _ksceIoOpenForPid(SceUID pid, const char *file, int flags, SceMode mode)
{
    int fid, ret;
    fopen_fd *ffd;

    if (strncmp(file, "host0", 5) != 0)
        return TAI_CONTINUE(SceUID, hooks[HOOK_IO_KOPEN2].ref, pid, file, flags, mode);

    if (sceGUIDKernelCreateWithOpt == NULL)
    {
        debugf("_ksceIoOpen2: sceGUIDKernelCreateWithOpt function pointer is NULL! Aborting...\n");
        return 0xDEADC0DE;
    }

    fid = open_host_fd(file, flags, mode);
    if (pid == KERNEL_PID) 
    {
        ret = (*sceGUIDKernelCreateWithOpt)(&p2sIoClass, "io_hook", NULL, (SceObjectBase **) &ffd);
    } 
    else 
    {
        SceCreateUidObjOpt opt;
        memset(&opt, 0, sizeof(opt));
        opt.flags = 8;
        opt.pid = (SceUInt32) pid;
        ret = (*sceGUIDKernelCreateWithOpt)(&p2sIoClass, "io_hook_user", &opt, (SceObjectBase **) &ffd);
    }

    if (ret < 0)
    {
        debugf("_ksceIoOpen2: sceGUIDKernelCreateWithOpt failed (0x%08X), pid: %X\n", ret, pid);
        return ret;
    }

    ffd->fd = fid;
    ffd->uid = ret;
    debugf("_ksceIoOpen2(%s, 0x%08X, 0x%08X): fid = %i, uid = 0x%08X\n", file, flags, mode, ffd->fd, ffd->uid);
    return ret;
}

int _ksceIoClose(SceUID uid)
{
    int res;
    fopen_fd *ffd;

    res = ksceGUIDReferObjectWithClass(uid, &p2sIoClass, (SceObjectBase **) &ffd);
    if (res < 0) 
    {
        debugf("ksceGUIDReferObjectWithClass(%x): 0x%08X\n", uid, res);
        return TAI_CONTINUE(int, hooks[HOOK_IO_KCLOSE].ref, uid);
    }

    res = close_host_fd(ffd->fd);
    debugf("_ksceIoClose(0x%08X) = 0x%08X\n", ffd->fd, res);
    ksceGUIDReleaseObject(uid);
    ksceGUIDClose(ffd->uid);
    return res;
}

int _ksceIoRead(SceUID uid, void *data, SceSize size)
{
    int res;
    fopen_fd *ffd;

    res = ksceGUIDReferObjectWithClass(uid, &p2sIoClass, (SceObjectBase **) &ffd);
    if (res < 0) 
    {
        debug2f("_ksceIoRead: ksceGUIDReferObjectWithClass(%x): 0x%08X\n", uid, res);
        return TAI_CONTINUE(int, hooks[HOOK_IO_KREAD].ref, uid, data, size);
    }

    res = io_read(ffd->fd, data, size);
    debug2f("_ksceIoRead(0x%08X, data, %i) = 0x%08X\n", ffd->fd, size, res);
    return res;
}

int _ksceIoWrite(SceUID uid, const void *data, SceSize size)
{
    int res;
    fopen_fd *ffd;

    res = ksceGUIDReferObjectWithClass(uid, &p2sIoClass, (SceObjectBase **) &ffd);
    if (res < 0)
    {
        debug2f("_ksceIoWrite: ksceGUIDReferObjectWithClass(%x): 0x%08X\n", uid, res);
        return TAI_CONTINUE(int, hooks[HOOK_IO_KWRITE].ref, uid, data, size);
    }

    res = io_write(ffd->fd, data, size);
    debug2f("_ksceIoWrite(0x%08X, data, %i) = 0x%08X\n", ffd->fd, size, res);
    return res;
}

SceOff _ksceIoLseek(SceUID uid, SceOff offset, int whence)
{
    SceOff res;
    fopen_fd *ffd;

    res = ksceGUIDReferObjectWithClass(uid, &p2sIoClass, (SceObjectBase **) &ffd);
    if (res < 0) 
    {
        debugf("_ksceIoLseek: ksceGUIDReferObjectWithClass(%x): 0x%08X\n", uid, res);
        return TAI_CONTINUE(SceOff, hooks[HOOK_IO_KLSEEK].ref, uid, offset, whence);
    }

    res = io_lseek(ffd->fd, offset, whence);
    debug2f("_ksceIoLseek(0x%08X, %lld, %i) == %lld\n", ffd->fd, offset, whence, res);
    return res;
}

int _ksceIoRemove(const char *file)
{
    if (strncmp(file, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KREMOVE].ref, file);

    int res = io_remove(file);
    debugf("_ksceIoRemove(%s) == 0x%08X\n", file, res);
    return res;
}

int _ksceIoRename(const char *oldname, const char *newname)
{
    if (strncmp(oldname, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KRENAME].ref, oldname, newname);

    int res = io_rename(oldname, newname);
    debugf("_ksceIoRename(%s, %s) == 0x%08X\n", oldname, newname, res);
    return res;
}

SceUID _ksceIoDopen(const char *dirname)
{
    if (strncmp(dirname, "host0", 5) != 0)
        return TAI_CONTINUE(SceUID, hooks[HOOK_IO_KDOPEN].ref, dirname);

    int res = open_host_dfd(dirname);
    debugf("_ksceIoDopen(%s) == 0x%08X\n", dirname, res);
    return res;
}

int _ksceIoDread(SceUID fd, SceIoDirent *dir)
{
    int res;

    if (is_host_fd(fd))
    {
        res = io_dread(fd, dir);
        debugf("_ksceIoDread(0x%08X) == 0x%08X\n", fd, res);
    }
    else
    {
        res = TAI_CONTINUE(int, hooks[HOOK_IO_KDREAD].ref, fd, dir);
    }
    return res;
}

int _ksceIoDclose(SceUID fd)
{
    int res;
    if (is_host_fd(fd))
    {
        res = close_host_dfd(fd);
        debugf("_ksceIoDclose(0x%08X) == 0x%08X\n", fd, res);
    }
    else
    {
        res = TAI_CONTINUE(int, hooks[HOOK_IO_KDCLOSE].ref, fd);
    }
    return res;
}

int _ksceIoMkdir(const char *dir, SceMode mode)
{
    if (strncmp(dir, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KMKDIR].ref, dir, mode);

    // int res = io_mkdir(dir, mode); TODO: fix mode ?
    int res = io_mkdir(dir, 6);
    debugf("_ksceIoMkdir(%s, 0x%08X) == 0x%08X\n", dir, mode, res);
    return res;
}

int _ksceIoRmdir(const char *path)
{
    if (strncmp(path, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KRMDIR].ref, path);

    int res = io_rmdir(path);
    debugf("_ksceIoRmdir(%s) == 0x%08X\n", path, res);
    return res;
}

int _ksceIoGetstat(const char *file, SceIoStat *stat)
{
    if (strncmp(file, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KGETSTAT].ref, file, stat);

    int res = io_getstat(file, stat);
    debugf("_ksceIoGetstat(%s) == 0x%08X (m=0x%08X a=0x%08X s=%i)\n", file, res, stat->st_mode, stat->st_attr, (int) stat->st_size);
    return res;
}

int _ksceIoGetstatByFd(SceUID fd, SceIoStat *stat)
{
    int res;

    if (is_host_fd(fd))
    {
        res = io_getstatbyfd(fd, stat);
        debugf("_ksceIoGetstatByFd(0x%08X) == 0x%08X (m=0x%08X a=0x%08X s=%i)\n", fd, res, stat->st_mode, stat->st_attr, (int) stat->st_size);
    }
    else
    {
        res = TAI_CONTINUE(int, hooks[HOOK_IO_KGETSTATBYFD].ref, fd, stat);
    }

    return res;
}

int _ksceIoChstat(const char *file, SceIoStat *stat, int bits)
{
    if (strncmp(file, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KCHSTAT].ref, file, stat, bits);

    int res = io_chstat(file, stat, bits);
    debugf("_ksceIoChstat(%s) == 0x%08X\n", file, res);

    return res;
}

int _ksceIoDevctl(const char *dev, unsigned int cmd, void *indata, int inlen, void *outdata, int outlen)
{
    if (strncmp(dev, "host0", 5) != 0)
        return TAI_CONTINUE(int, hooks[HOOK_IO_KDEVCTL].ref, dev, cmd, indata, inlen, outdata, outlen);

    int res = io_devctl(dev, cmd, indata, inlen, outdata, outlen);
    debugf("_ksceIoDevctl(%s, 0x%08X) == 0x%08X\n", dev, cmd, res);

    return res;
}

static int init_class(void *ffd)
{
    fopen_fd *fd = (fopen_fd *)ffd;
    debugf("init_class: %p\n", fd);
    return 0;
}

static int free_class(void *ffd)
{
    fopen_fd *fd = (fopen_fd *)ffd;
    debugf("free_class: %p\n", fd);
    return 0;
}

void set_hooks_io()
{
    int ret = module_get_export_func(KERNEL_PID, "SceSysmem", 0x63A519E5, 0x53E1FFDE, (uintptr_t*)&sceGUIDKernelCreateWithOpt);
    if (ret < 0) // probably 3.65
    {
        ret = module_get_export_func(KERNEL_PID, "SceSysmem", 0x02451F0F, 0x6D26B066, (uintptr_t*)&sceGUIDKernelCreateWithOpt);
        if (ret < 0) // uh oh, something bad happened.
        {
            debugf("module_get_export_func: failed to get sceGUIDKernelCreateWithOpt, ret: 0x%08X\n", ret);
            return;
        }
        debugf("module_get_export_func: got sceGUIDKernelCreateWithOpt (3.65), ret: 0x%08X\n", ret);
    }
    else
    {
        debugf("module_get_export_func: got sceGUIDKernelCreateWithOpt (3.60), ret: 0x%08X\n", ret);
    }

    ret = ksceUIDClassInitClass(&p2sIoClass, "p2sIoClass", ksceKernelGetUIDClass(), sizeof(fopen_fd), init_class, free_class);
    debugf("ksceUIDClassInitClass(p2sIoClass): 0x%08X\n", ret);

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        host_fds[i] = -1;
    }

    for (int i = 0; i < HOOK_END; i++)
    {
        hooks[i].uid = taiHookFunctionExportForKernel(
                KERNEL_PID,
                &hooks[i].ref,
                hooks[i].name,
                hooks[i].lib,
                hooks[i].nid,
                hooks[i].func);
    }
}

void delete_hooks_io()
{
    for (int i = 0; i < HOOK_END; i++)
    {
        if (hooks[i].uid >= 0)
            taiHookReleaseForKernel(hooks[i].uid, hooks[i].ref);
    }

    for (int i = 0; i < MAX_HOST_FD; i++)
    {
        if (host_fds[i] >= 0)
            io_close(host_fds[i]);
    }
}
