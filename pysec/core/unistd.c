/*
 * Python Security Project (PySec) and its related class files.
 *
 * PySec is a set of tools for secure application development under Linux
 *
 * Copyright 2014 PySec development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>


/* from posix_module */
/* Issue #1983: pid_t can be longer than a C long on some systems */
#if !defined(SIZEOF_PID_T) || SIZEOF_PID_T == SIZEOF_INT
#define PARSE_PID "i"
#define PyLong_FromPid PyInt_FromLong
#define PyLong_AsPid PyInt_AsLong
#elif SIZEOF_PID_T == SIZEOF_LONG
#define PARSE_PID "l"
#define PyLong_FromPid PyInt_FromLong
#define PyLong_AsPid PyInt_AsLong
#elif defined(SIZEOF_LONG_LONG) && SIZEOF_PID_T == SIZEOF_LONG_LONG
#define PARSE_PID "L"
#define PyLong_FromPid PyLong_FromLongLong
#define PyLong_AsPid PyInt_AsLongLong
#else
#error "sizeof(pid_t) is neither sizeof(int), sizeof(long) or sizeof(long long)"
#endif /* SIZEOF_PID_T */

#define VALID_SALT_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"

PyDoc_STRVAR(unistd_access__doc__,
"The access() function shall check the file named by the pathname pointed to\n"
"by the path argument for accessibility according to the bit pattern contained\n"
"in amode, using the real user ID in place of the effective user ID and the\n"
"real group ID in place of the effective group ID.\n"
"The value of amode is either the bitwise-inclusive OR of the access\n"
"permissions to be checked (R_OK, W_OK, X_OK) or the existence test (F_OK).\n"
"If any access permissions are checked, each shall be checked individually,\n"
"as described in the Base Definitions volume of IEEE Std 1003.1-2001,\n"
"Chapter 3, Definitions. If the process has appropriate privileges, an\n"
"implementation may indicate success for X_OK even if none of the execute\n"
"file permission bits are set.\n\n"
"If the requested access is permitted, access() succeeds and shall return 0;\n"
"otherwise, errno shall be returned to indicate the error.\n\n"
"Errors: EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR, EROFS, EINVAL, ETXTBSY\n"
"ENAMETOOLONG");

/*@null@*/
static PyObject*
unistd_access(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int amode = R_OK;
    static char *kwlist[] = {"path", "amode", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|i:access", kwlist,
                                    &path, &amode))
        return NULL;
    return PyInt_FromLong(access(path, amode) == 0 ? 0 : errno);
}

PyDoc_STRVAR(unistd_alarm__doc__,
"The alarm() function shall cause the system to generate a SIGALRM signal for\n"
"the process after the number of realtime seconds specified by seconds have\n"
"elapsed. Processor scheduling delays may prevent the process from handling\n"
"the signal as soon as it is generated.\n\n"
"If seconds is 0, a pending alarm request, if any, is canceled.\n\n"
"Alarm requests are not stacked; only one SIGALRM generation can be scheduled\n"
"in this manner. If the SIGALRM signal has not yet been generated, the call\n"
"shall result in rescheduling the time at which the SIGALRM signal is\n"
"generated.\n\n"
"Interactions between alarm() and any of setitimer(), ualarm(), or usleep()\n"
"are unspecified\n\n"
"If there is a previous alarm() request with time remaining, alarm() shall\n"
"return a non-zero value that is the number of seconds until the previous\n"
"request would have generated a SIGALRM signal. Otherwise, alarm() shall\n"
"return 0.");

/*@null@*/
static PyObject*
unistd_alarm(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    unsigned seconds = 0;
    static char *keywords[] = {"seconds", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "I:alarm", keywords, &seconds))
        return NULL;
    return Py_BuildValue("I", alarm(seconds));
}

PyDoc_STRVAR(unistd_chdir__doc__,
"The chdir() function shall cause the directory named by the pathname pointed\n"
"to by the path argument to become the current working directory; that is,\n"
"the starting point for path searches for pathnames not beginning with '/'.\n"
"Upon successful completion, 0 shall be returned. Otherwise, errno shall be\n"
"returned, the current working directory shall remain unchanged\n\n"
"Errors: EACCES, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR,");

/*@null@*/
static PyObject*
unistd_chdir(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int ret;
    static char *kwlist[] = {"path", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s:chdir", kwlist, &path))
        return NULL;
    return PyInt_FromLong((ret=chdir(path)) == 0 ? 0 : errno);
}

PyDoc_STRVAR(unistd_chown__doc__,
"The chown() function shall change the user and group ownership of a file.\n"
"The path argument points to a pathname naming a file. The user ID and group\n"
"ID of the named file shall be set to the numeric values contained in owner\n"
"and group, respectively.\n"
"Only processes with an effective user ID equal to the user ID of the file or\n"
"with appropriate privileges may change the ownership of a file.\n"
"If _POSIX_CHOWN_RESTRICTED is in effect for path:\n"
"   - Changing the user ID is restricted to processes with appropriate\n"
"privileges.\n"
"   - Changing the group ID is permitted to a process with an effective user\n"
"     ID equal to the user ID of the file, but without appropriate privileges,\n"
"     if and only if owner is equal to the file's user ID or ( uid_t)-1 and\n"
"     group is equal either to the calling process' effective group ID or to\n"
"     one of its supplementary group IDs.\n\n"
"If the specified file is a regular file, one or more of the S_IXUSR,\n"
"S_IXGRP, or S_IXOTH bits of the file mode are set, and the process does not\n"
"have appropriate privileges, the set-user-ID (S_ISUID) and set-group-ID\n"
"(S_ISGID) bits of the file mode shall be cleared upon successful return from\n"
"chown(). If the specified file is a regular file, one or more of the\n"
"S_IXUSR, S_IXGRP, or S_IXOTH bits of the file mode are set, and the process\n"
"has appropriate privileges, it is implementation-defined whether the\n"
"set-user-ID and set-group-ID bits are altered. If the chown() function is\n"
"successfully invoked on a file that is not a regular file and one or more of\n"
"the S_IXUSR, S_IXGRP, or S_IXOTH bits of the file mode are set, the\n"
"set-user-ID and set-group-ID bits may be cleared.\n"
"If owner or group is specified as ( uid_t)-1 or ( gid_t)-1, respectively,\n"
"the corresponding ID of the file shall not be changed. If both owner and\n"
"group are -1, the times need not be updated.\n"
"Upon successful completion, chown() shall mark for update the st_ctime field\n"
" of the file.\n\n"
"Upon successful completion, 0 shall be returned; otherwise, errno shall be\n"
"returned and no changes are made in the user ID and group ID of the file.\n\n"
"Errors: EACCES, ELOOP, ENAMETOOLONG, ENOTDIR, ENOENT, EPERM, EROFS, EIO,\n"
"EINTR, EINVAL");

/*@null@*/
static PyObject*
unistd_chown(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int ret;

    uid_t owner = -1;
    gid_t group = -1;
    static char *kwlist[] = {"path", "owner", "group", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|" PARSE_PID PARSE_PID ":chown",
                                    kwlist, &path, &owner, &group))
        return NULL;
    return PyInt_FromLong((ret=chown(path, owner, group)) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_close__doc__,
"The close() function shall deallocate the file descriptor indicated by fildes.\n"
"To deallocate means to make the file descriptor available for return by\n"
"subsequent calls to open() or other functions that allocate file descriptors.\n"
"All outstanding record locks owned by the process on the file associated with\n"
"the file descriptor shall be removed (that is, unlocked).\n"
"If close() is interrupted by a signal that is to be caught, it shall return\n"
"-1 with errno set to [EINTR] and the state of fildes is unspecified.\n"
"If an I/O error occurred while reading from or writing to the file system\n"
"during close(), it may return -1 with errno set to [EIO]; if this error is\n"
"returned, the state of fildes is unspecified.\n\n"
"When all file descriptors associated with a pipe or FIFO special file are\n"
"closed, any data remaining in the pipe or FIFO shall be discarded.\n"
"When all file descriptors associated with an open file description have been\n"
"closed, the open file description shall be freed.\n"
"If the link count of the file is 0, when all file descriptors associated with\n"
"the file are closed, the space occupied by the file shall be freed and the\n"
"file shall no longer be accessible.\n\n"
"[XSR]\n"
"If a STREAMS-based fildes is closed and the calling process was previously\n"
"registered to receive a SIGPOLL signal for events associated with that STREAM,\n"
"the calling process shall be unregistered for events associated with the\n"
"STREAM. The last close() for a STREAM shall cause the STREAM associated with\n"
"fildes to be dismantled. If O_NONBLOCK is not set and there have been no\n"
"signals posted for the STREAM, and if there is data on the module's write\n"
"queue, close() shall wait for an unspecified time (for each module and driver)\n"
"for any output to drain before dismantling the STREAM. The time delay can be\n"
"changed via an I_SETCLTIME ioctl() request. If the O_NONBLOCK flag is set, or\n"
"if there are any pending signals, close() shall not wait for output to drain,\n"
"and shall dismantle the STREAM immediately.\n\n"
"If the implementation supports STREAMS-based pipes, and fildes is associated\n"
"with one end of a pipe, the last close() shall cause a hangup to occur on the\n"
"other end of the pipe. In addition, if the other end of the pipe has been named\n"
"by fattach(), then the last close() shall force the named end to be detached by\n"
"fdetach(). If the named end has no open file descriptors associated with it\n"
"and gets detached, the STREAM associated with that end shall also be dismantled.\n\n"
"[XSI]\n"
"If fildes refers to the master side of a pseudo-terminal, and this is the last\n"
"close, a SIGHUP signal shall be sent to the controlling process, if any, for\n"
"which the slave side of the pseudo-terminal is the controlling terminal. It is\n"
"unspecified whether closing the master side of the pseudo-terminal flushes all\n"
"queued input and output.\n\n"
"[XSR]\n"
"If fildes refers to the slave side of a STREAMS-based pseudo-terminal, a\n"
"zero-length message may be sent to the master.\n\n"
"[AIO]\n"
"When there is an outstanding cancelable asynchronous I/O operation against\n"
"fildes when close() is called, that I/O operation may be canceled. An I/O\n"
"operation that is not canceled completes as if the close() operation had not\n"
"yet occurred. All operations that are not canceled shall complete as if the\n"
"close() blocked until the operations completed. The close() operation itself\n"
"need not block awaiting such I/O completion. Whether any I/O operation is\n"
"canceled, and which I/O operation may be canceled upon close(), is\n"
"implementation-defined.\n\n"
"[MF|SHM]\n"
"If a shared memory object or a memory mapped file remains referenced at the\n"
"last close (that is, a process has it mapped), then the entire contents of the\n"
"memory object shall persist until the memory object becomes unreferenced. If\n"
"this is the last close of a shared memory object or a memory mapped file and\n"
"the close results in the memory object becoming unreferenced, and the memory\n"
"object has been unlinked, then the memory object shall be removed.\n\n"
"If fildes refers to a socket, close() shall cause the socket to be destroyed.\n"
"If the socket is in connection-mode, and the SO_LINGER option is set for the\n"
"socket with non-zero linger time, and the socket has untransmitted data, then\n"
"close() shall block for up to the current linger interval until all data is\n"
"transmitted.\n\n"
"Upon successful completion, 0 shall be returned; otherwise, errno shall be\n"
"returned");

/*@null@*/
static PyObject*
unistd_close(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:close", kwlist, &fildes))
        return NULL;
    return PyInt_FromLong(close(fildes) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_confstr__doc__,
"The confstr() function shall return configuration-defined string values.\n"
"Its use and purpose are similar to sysconf(), but it is used where string\n"
"values rather than numeric values are returned.\n"
"The name argument represents the system variable to be queried.\n"
"The implementation shall support the following name values, defined in\n"
"<unistd.h>");

/*@null@*/
static PyObject*
unistd_confstr(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int name;
    char *buf;
    size_t len;
    PyObject *res;
    static char *kwlist[] = {"name", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:confstr", kwlist, &name))
        return NULL;
    if((len=confstr(name, NULL, 0)) == 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    if((buf=PyMem_New(char, len)) == NULL)
        return PyErr_NoMemory();
    confstr(name, buf, len);
    res = PyString_FromString(buf);
    PyMem_Free(buf);
    return res;
}

PyDoc_STRVAR(unistd_crypt__doc__,
"The crypt() function is a string encoding function. The algorithm is\n"
"implementation-defined.\n"
"The key argument points to a string to be encoded. The salt argument is a\n"
"string chosen from the set:\n\n"
"a b c d e f g h i j k l m n o p q r s t u v w x y z\n"
"A B C D E F G H I J K L M N O P Q R S T U V W X Y Z\n"
"0 1 2 3 4 5 6 7 8 9 . /\n\n"
"The first two characters of this string may be used to perturb the encoding\n"
"algorithm.\n"
"The crypt() function need not be reentrant. A function that is not required\n"
"to be reentrant is not required to be thread-safe.\n\n"
"Errors: ENOSYS.");

/*@null@*/
PyObject*
unistd_crypt(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int end;
    char *key,
         *salt,
         *enc;
    static char *kwlist[] = {"key", "salt", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "ss:crypt", kwlist, &key, &salt))
        return NULL;
    if((end=strspn(salt, VALID_SALT_CHARS)) != strlen(salt))
    {
        PyErr_Format(PyExc_ValueError, "invalid character '%x'", salt[end]);
        return NULL;
    }
    enc = crypt(key, salt);
    if(enc==NULL)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyString_FromString(enc);
}


PyDoc_STRVAR(unistd_ctermid__doc__,
"The ctermid() function shall generate a string that, when used as a pathname,\n"
"refers to the current controlling terminal for the current process.\n"
"If ctermid() returns a pathname, access to the file is not guaranteed.\n"
"If the application uses any of the _POSIX_THREAD_SAFE_FUNCTIONS or\n"
"_POSIX_THREADS functions, it shall ensure that the ctermid() function is called\n"
"with a non-NULL parameter.\n\n");

PyObject*
unistd_ctermid(/*@unused@*/  PyObject* self)
{
    char *s;
    PyObject *res;
    s = PyMem_New(char, L_ctermid);
    ctermid(s);
    res = PyString_FromString(s);
    PyMem_Free(s);
    return res;
}

PyDoc_STRVAR(unistd_dup__doc__,
"The dup()functions provide an alternative interface to the service\n"
"provided by fcntl() using the F_DUPFD command.\n"
"Upon successful completion a non-negative integer, namely the file descriptor,\n"
"shall be returned; otherwise, -1 shall be returned and errno set to indicate\n"
"the error.");

/*@null@*/
PyObject*
unistd_dup(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes,
        ret;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:dup", kwlist, &fildes))
        return NULL;
    if((ret=dup(fildes)) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(ret);
}

PyDoc_STRVAR(unistd_dup2__doc__,
"The dup2()functions provide an alternative interface to the service\n"
"provided by fcntl() using the F_DUPFD command.\n"
"dup2(fildes, fildes2) shall be equivalent to:\n\n"
"   close(fildes2);\n"
"   fid = fcntl(fildes, F_DUPFD, fildes2);\n\n"
"except for the following:\n"
"   If fildes2 is less than 0 or greater than or equal to {OPEN_MAX}, dup2()\n"
"   shall return -1 with errno set to [EBADF].\n\n"
"   If fildes is a valid file descriptor and is equal to fildes2, dup2() shall\n"
"   return fildes2 without closing it.\n\n"
"   If fildes is not a valid file descriptor, dup2() shall return -1 and shall\n"
"   not close fildes2.\n\n"
"   The value returned shall be equal to the value of fildes2 upon successful\n"
"   completion, or -1 upon failure.\n\n"
"Upon successful completion a non-negative integer, namely the file descriptor,\n"
"shall be returned; otherwise, -1 shall be returned and errno set to indicate\n"
"the error.\n\n"
"Errors: EBADF, EMFILE, EINTR");

/*@null@*/
PyObject*
unistd_dup2(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes,
        fildes2,
        ret;
    static char *kwlist[] = {"fildes", "fildes2", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "ii:dup", kwlist,
                                    &fildes, &fildes2))
        return NULL;
    if((ret=dup2(fildes, fildes2)) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(ret);
}


PyDoc_STRVAR(unistd_encrypt__doc__,
"The encrypt() function shall provide access to an implementation-defined\n"
"encoding algorithm. The key generated by setkey() is used to encrypt the string\n"
"block with encrypt().\n\n"
"The block argument to encrypt() shall be an string of length 64 containing\n"
"only the values of '0' and '1'. The array is modified in place to a\n"
"similar array using the key set by setkey(). If edflag is 0, the argument is\n"
"encoded. If edflag is 1, the argument may be decoded (see the APPLICATION USAGE\n"
"section); if the argument is not decoded, errno shall be set to [ENOSYS].\n"
"The encrypt() function shall not change the setting of errno if successful.\n"
"An application wishing to check for error situations should set errno to 0\n"
"before calling encrypt(). If errno is non-zero on return, an error has occurred.\n"
"The encrypt() function need not be reentrant. A function that is not required\n"
"to be reentrant is not required to be thread-safe.");

/*@null@*/
PyObject*
unistd_encrypt(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    char *block;
    PyObject *ef_obj = Py_True;
    int block_len,
        edflag,
        end;

    static char *kwlist[] = {"block", "edflag", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s|O:dup", kwlist,
                                    &block, &ef_obj))
        return NULL;
    if((block_len = strlen(block)) != 64)
        return PyErr_Format(PyExc_ValueError,
                            "block must be 64 length string, not %d", block_len);
    if((end=strspn(block, "01")) != strlen(block))
        return PyErr_Format(PyExc_ValueError, "block must have only 0 or 1"
                            "characters, not %x", block[end]);
    
    if((edflag=PyObject_IsTrue(ef_obj)) < 0)
        return NULL;
    encrypt(block, edflag);
    return PyString_FromStringAndSize(block, 64);
}

/*

int          execl(const char *, const char *, ...);
int          execle(const char *, const char *, ...);
int          execlp(const char *, const char *, ...);
int          execv(const char *, char *const []);
int          execve(const char *, char *const [], char *const []);
int          execvp(const char *, char *const []);

TODO - add here...

*/


PyDoc_STRVAR(unistd__exit__doc__,
"The functionality described on this reference page is aligned with the ISO C\n"
"standard. Any conflict between the requirements described here and the ISO C\n"
"standard is unintentional. This volume of IEEE Std 1003.1-2001 defers to the\n"
"ISO C standard.\n"
"The value of status may be 0, EXIT_SUCCESS, EXIT_FAILURE, [CX] or any other\n"
"value, though only the least significant 8 bits (that is, status & 0377) shall\n"
"be available to a waiting parent process.\n"
"The _exit()  functions shall not call functions registered with atexit() nor\n"
"any registered signal handlers. Whether open streams are flushed or closed, or\n"
"temporary files are removed is implementation-defined. Finally, the calling\n"
"process is terminated with the consequences described below.\n");
/* TODO not complete */

/*@null@*/
static PyObject*
unistd__exit(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int status=0;
    static char *kwlist[] = {"status", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i:dup", kwlist, &status))
        return NULL;
    _exit(status);
    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(unistd_fchdir__doc__,
"The fchdir() function shall be equivalent to chdir() except that the directory\n"
"that is to be the new current working directory is specified by the file\n"
"descriptor fildes.\n"
"A conforming application can obtain a file descriptor for a file of type\n"
"directory using open(), provided that the file status flags and access modes\n"
"do not contain O_WRONLY or O_RDWR.\n"
"Upon successful completion, fchdir() shall return 0. Otherwise, it shall return\n"
"-1 and set errno to indicate the error. On failure the current working directory\n"
"shall remain unchanged.\n\n"
"Errors: EACCES, EBADF, ENOTDIR, EINTR, EIO.");

/*@null@*/
static PyObject*
unistd_fchdir(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:dup", kwlist, &fildes))
        return NULL;
    return PyInt_FromLong(fchdir(fildes) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_fchown__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_fchown(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;

    uid_t owner = -1;
    gid_t group = -1;
    static char *kwlist[] = {"fildes", "owner", "group", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i|kk:chown", kwlist,
                                    &fildes, &owner, &group))
        return NULL;
    return PyInt_FromLong(fchown(fildes, owner, group) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_fdatasync__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_fdatasync(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:fdatasync", kwlist, &fildes))
        return NULL;
    return PyInt_FromLong(fdatasync(fildes) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_fork__doc__,
"");
/* TODO - doc */

static PyObject*
unistd_fork(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(fork());
}


PyDoc_STRVAR(unistd_fpathconf__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_fpathconf(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes,
        name;
    static char *kwlist[] = {"fildes", "name", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "ii:fpathconf", kwlist,
                                    &fildes, &name))
        return NULL;
    errno = 0;
    return PyInt_FromLong(fpathconf(fildes, name) == -1 ? -1 : errno);
}


PyDoc_STRVAR(unistd_fsync__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_fsync(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:fsync", kwlist, &fildes))
        return NULL;
    return PyInt_FromLong(fsync(fildes) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_ftruncate__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_ftruncate(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes,
        length;
    static char *kwlist[] = {"fildes", "length", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "ii:ftruncate", kwlist,
                                    &fildes, &length))
        return NULL;
    return PyInt_FromLong(ftruncate(fildes, length) == 0 ? 0 : errno);
}

PyDoc_STRVAR(unistd_getcwd__doc__,
"");
/* TODO - doc */

#define INCREMENT   1024

static PyObject*
unistd_getcwd(/*@unused@*/  PyObject* self)
{
    /* from posixmodule.c */
    int bufsize = 0;
    char *tmpbuf = NULL,
         *tmpres = NULL;
    PyObject *res;

    Py_BEGIN_ALLOW_THREADS
    do {
        bufsize += INCREMENT;
        tmpbuf = PyMem_New(char, bufsize);
        if (tmpbuf == NULL)
            break;
        tmpres = getcwd(tmpbuf, bufsize);
        if (tmpres == NULL)
            PyMem_Free(tmpbuf);
    } while (tmpres == NULL && errno == ERANGE);
    Py_END_ALLOW_THREADS

    if (tmpres == NULL)
        return PyErr_SetFromErrno(PyExc_OSError);
        

    res = PyString_FromString(tmpbuf);
    PyMem_Free(tmpbuf);
    return res; /* TODO BuildValue */
}


PyDoc_STRVAR(unistd_getegid__doc__,
"");
/* TODO - doc */

PyObject*
unistd_getegid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getegid());
}


PyDoc_STRVAR(unistd_geteuid__doc__,
"");
/* TODO - doc */

PyObject*
unistd_geteuid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(geteuid());
}

PyDoc_STRVAR(unistd_getgid__doc__,
"");
/* TODO - doc */

PyObject*
unistd_getgid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getgid());
}


PyDoc_STRVAR(unistd_getgroups__doc__,
"The getgroups() function shall return a grouplist with the current\n"
"supplementary group IDs of the calling process. It is implementation-defined\n"
"whether getgroups() also returns the effective group ID in the grouplist array.\n");
/* TODO - doc */

static PyObject *
unistd_getgroups(PyObject *self)
{
    PyObject *result = NULL;

#ifdef NGROUPS_MAX
#define MAX_GROUPS NGROUPS_MAX
#else
    /* defined to be 16 on Solaris7, so this should be a small number */
#define MAX_GROUPS 64
#endif
    gid_t grouplist[MAX_GROUPS];
    int n;

    n = getgroups(MAX_GROUPS, grouplist);
    if (n < 0)
        PyErr_SetFromErrno(PyExc_OSError);
    else {
        result = PyList_New(n);
        if (result != NULL) {
            int i;
            for (i = 0; i < n; ++i) {
                PyObject *o = PyInt_FromLong((long)grouplist[i]);
                if (o == NULL) {
                    Py_DECREF(result);
                    result = NULL;
                    break;
                }
                PyList_SET_ITEM(result, i, o);
            }
        }
    }

    return result;
}


PyDoc_STRVAR(unistd_gethostid__doc__,
"The gethostid() function shall retrieve a 32-bit identifier for the current\n"
"host.\n"
"Upon successful completion, gethostid() shall return an identifier for the\n"
"current host.");

static PyObject *
unistd_gethostid(PyObject *self)
{
    return PyInt_FromLong(gethostid());
}

PyDoc_STRVAR(unistd_getlogin__doc__,
"The getlogin() function shall return a string containing the user name\n"
"associated by the login activity with the controlling terminal of the current\n"
"process.");
/* TODO - doc */

static PyObject *
unistd_getlogin(PyObject *self)
{
    char *name;
    if((name=getlogin()) == NULL)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyString_FromString(name);
}


PyDoc_STRVAR(unistd_getpgid__doc__,
"The getpgid() function shall return the process group ID of the process whose\n"
"process ID is equal to pid. If pid is equal to 0, getpgid() shall return the\n"
"process group ID of the calling process.\n\n"
"Upon successful completion, getpgid() shall return a process group ID.\n"
"Otherwise, it shall return (pid_t)-1 and set errno to indicate the error.\n"
"Errors: EPERM, ESRCH, EINVAL");

/*@null@*/
PyObject*
unistd_getpgid(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    pid_t pid;
    static char *kwlist[] = {"pid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID ":ftruncate",
                                    kwlist, &pid))
        return NULL;
    if((pid=getpgid(pid)) == -1)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyLong_FromPid(pid);
}


PyDoc_STRVAR(unistd_getpgrp__doc__,
"The getpgrp() function shall return the process group ID of the calling\n"
"process.");

PyObject*
unistd_getpgrp(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getpgrp());
}


PyDoc_STRVAR(unistd_getpid__doc__,
"The getpid() function shall return the process ID of the calling process.");

PyObject*
unistd_getpid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getpid());
}


PyDoc_STRVAR(unistd_getppid__doc__,
"The getppid() function shall return the parent process ID of the calling\n"
"process.");

PyObject*
unistd_getppid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getppid());
}


PyDoc_STRVAR(unistd_getsid__doc__,
"The getsid() function shall obtain the process group ID of the process that is\n"
"the session leader of the process specified by pid. If pid is (pid_t)0, it\n"
"specifies the calling process.\n\n"
"Errors: EPERM, ESRCH.");

/*@null@*/
PyObject*
unistd_getsid(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    pid_t pid,
          sid;
    static char *kwlist[] = {"pid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID ":getsid", kwlist, &pid))
        return NULL;
    sid = getsid(pid);
    if (sid < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(sid);
}


PyDoc_STRVAR(unistd_getuid__doc__,
"The getuid() function shall return the real user ID of the calling process.");

PyObject*
unistd_getuid(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(getuid());
}


PyDoc_STRVAR(unistd_isatty__doc__,
"The isatty() function shall return the real user ID of the calling process.");

/*@null@*/
PyObject*
unistd_isatty(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    static char *kwlist[] = {"fildes", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:isatty", kwlist, &fildes))
        return NULL;
    errno = 0;
    if(isatty(fildes) == 0) {
        if(errno)
            return PyErr_SetFromErrno(PyExc_OSError);
        Py_RETURN_FALSE;
    }
    else
        Py_RETURN_TRUE;
}


PyDoc_STRVAR(unistd_setgid__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject *
unistd_setgid(PyObject *self, PyObject *args, PyObject *kwds)
{
    gid_t gid;
    static char *kwlist[] = {"gid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID ":setgid",
                                    kwlist, &gid))
        return NULL;
    if (setgid(gid) < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    Py_INCREF(Py_None);
    return Py_None;
}


PyDoc_STRVAR(unistd_setpgid__doc__,
"The setpgid() function shall either join an existing process group or create a\n"
"new process group within the session of the calling process. The process group\n"
"ID of a session leader shall not change. Upon successful completion, the process\n"
"group ID of the process with a process ID that matches pid shall be set to pgid.\n"
"As a special case, if pid is 0, the process ID of the calling process shall be\n"
"used. Also, if pgid is 0, the process ID of the indicated process shall be used.");

/*@null@*/
static PyObject *
unistd_setpgid(PyObject *self, PyObject *args, PyObject *kwds)
{
    pid_t pid,
          pgid;
    static char *kwlist[] = {"pid", "pgid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID PARSE_PID ":setpgid",
                                    kwlist, &pid, &pgid))
        return NULL;
    return PyInt_FromLong(setpgid(pid, pgid) == 0 ? 0 : errno);
}

PyDoc_STRVAR(unistd_setregid__doc__,
"");

/*@null@*/
static PyObject *
unistd_setregid(PyObject *self, PyObject *args, PyObject *kwds)
{
    pid_t rgid,
          egid;
    static char *kwlist[] = {"rgid", "egid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID PARSE_PID ":setregid",
                                    kwlist, &rgid, &egid))
        return NULL;
    return PyInt_FromLong(setregid(rgid, egid) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_setreuid__doc__,
"");

/*@null@*/
static PyObject *
unistd_setreuid(PyObject *self, PyObject *args, PyObject *kwds)
{
    pid_t ruid,
          euid;
    static char *kwlist[] = {"ruid", "euid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID PARSE_PID ":setreuid",
                                    kwlist, &ruid, &euid))
        return NULL;
    return PyInt_FromLong(setreuid(ruid, euid) == 0 ? 0 : errno);
}

PyDoc_STRVAR(unistd_setsid__doc__,
"");

static PyObject *
unistd_setsid(PyObject *self)
{
    pid_t res;
    if ((res=setsid()) == -1)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyLong_FromPid(res);
}


PyDoc_STRVAR(unistd_setuid__doc__,
"");

/*@null@*/
static PyObject *
unistd_setuid(PyObject *self, PyObject *args, PyObject *kwds)
{
    uid_t uid;
    static char *kwlist[] = {"uid", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, PARSE_PID ":setuid",
                                    kwlist, &uid))
        return NULL;
    return PyInt_FromLong(setuid(uid) == 0 ? 0 : errno);
}


PyDoc_STRVAR(unistd_sleep__doc__,
"");

/*@null@*/
static PyObject *
unistd_sleep(PyObject *self, PyObject *args, PyObject *kwds)
{
    unsigned seconds;
    static char *kwlist[] = {"seconds", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "I:sleep", kwlist, &seconds))
        return NULL;
    return Py_BuildValue("I", sleep(seconds));
}


PyDoc_STRVAR(unistd_nice__doc__,
"The nice() function shall add the value of incr to the nice value of the\n"
"calling process. A process' nice value is a non-negative number for which a\n"
"more positive value shall result in less favorable scheduling.\n"
"A maximum nice value of 2*{NZERO}-1 and a minimum nice value of 0 shall be\n"
"imposed by the system. Requests for values above or below these limits shall\n"
"result in the nice value being set to the corresponding limit. Only a process\n"
"with appropriate privileges can lower the nice value.\n\n"
"[PS|TPS]\n"
"Calling the nice() function has no effect on the priority of processes or\n"
"threads with policy SCHED_FIFO or SCHED_RR. The effect on processes or threads\n"
"with other scheduling policies is implementation-defined.\n\n"
"The nice value set with nice() shall be applied to the process. If the process\n"
"is multi-threaded, the nice value shall affect all system scope threads in the\n"
"process.\n"
"As -1 is a permissible return value in a successful situation, an application\n"
"wishing to check for error situations should set errno to 0, then call nice(),\n"
"and if it returns -1, check to see whether errno is non-zero.\n\n"
"Upon successful completion, nice() shall return the new nice value -{NZERO}.\n"
"Otherwise, -1 shall be returned, the process' nice value shall not be changed,\n"
"and errno shall be set to indicate the error.");

/*@null@*/
static PyObject*
unistd_nice(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int incr=0;
    static char *kwlist[] = {"incr", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|i:nice", kwlist, &incr))
        return NULL;
    errno = 0;
    incr = nice(incr);
    if(incr == -1 && errno)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(incr);
}

PyDoc_STRVAR(unistd_pathconf__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_pathconf(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int name;
    static char *kwlist[] = {"path", "name", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "si:pathconf", kwlist,
                                    &path, &name))
        return NULL;
    errno = 0;
    /* TODO - check */
    return PyInt_FromLong(pathconf(path, name) == -1 ? -1 : errno);
}

PyDoc_STRVAR(unistd_vfork__doc__,
"The vfork() function shall be equivalent to fork(), except that the behavior\n"
"is undefined if the process created by vfork() either modifies any data other\n"
"than a variable of type pid_t used to store the return value from vfork(), or\n"
"returns from the function in which vfork() was called, or calls any other\n"
"function before successfully calling _exit() or one of the exec family of\n"
"functions.\n"
"Upon successful completion, vfork() shall return 0 to the child process and\n"
"return the process ID of the child process to the parent process. Otherwise,\n"
"-1 shall be returned to the parent, no child process shall be created, and\n"
"errno shall be set to indicate the error.");

static PyObject*
unistd_vfork(/*@unused@*/  PyObject* self)
{
    return PyLong_FromPid(vfork());
}

PyDoc_STRVAR(unistd_read__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_read(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    char *buf;
    Py_ssize_t nbytes, rbytes;
    PyObject *res;
    static char *kwlist[] = {"fildes", "size", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "in:pread", kwlist,
                                    &fildes, &nbytes))
        return NULL;
    if((buf = (void *)PyMem_New(int8_t, nbytes)) == NULL)
        return PyErr_NoMemory();
    rbytes = read(fildes, buf, nbytes);
    if (rbytes < 0)
        return PyErr_SetFromErrno(PyExc_IOError);
    res = PyString_FromStringAndSize(buf, rbytes);
    PyMem_Free(buf);
    return res;
}

PyDoc_STRVAR(unistd_pread__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_pread(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    char *buf;
    Py_ssize_t nbytes, rbytes;
    off_t offset;
    PyObject *res;
    static char *kwlist[] = {"fildes", "size", "offset", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "inK:pread", kwlist,
                                    &fildes, &nbytes, &offset))
        return NULL;
    if((buf = (void *)PyMem_New(int8_t, nbytes)) == NULL)
        return PyErr_NoMemory();
    rbytes = pread(fildes, buf, nbytes, offset);
    if (rbytes < 0)
        return PyErr_SetFromErrno(PyExc_IOError);
    res = PyString_FromStringAndSize(buf, rbytes);
    PyMem_Free(buf);
    return res;
}


PyDoc_STRVAR(unistd_write__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_write(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    char *buf;
    Py_ssize_t nbytes, wbytes;
    static char *kwlist[] = {"fildes", "buf", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "is#:write", kwlist,
                                    &fildes, &buf, &nbytes))
        return NULL;
    errno = 0;
    /* TODO - check */
    Py_BEGIN_ALLOW_THREADS
    wbytes = write(fildes, buf, nbytes);
    Py_END_ALLOW_THREADS
    if (nbytes < 0)
        return PyErr_SetFromErrno(PyExc_IOError);
    return PyInt_FromSize_t(wbytes);
}


PyDoc_STRVAR(unistd_pwrite__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
unistd_pwrite(/*@unused@*/  PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes;
    char *buf;
    Py_ssize_t nbytes, wbytes;
    off_t offset;
    static char *kwlist[] = {"fildes", "buf", "offset", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "is#K:pwrite", kwlist,
                                    &fildes, &buf, &nbytes, &offset))
        return NULL;
    errno = 0;
    /* TODO - check */
    wbytes = pwrite(fildes, buf, nbytes, offset);
    if (nbytes < 0)
        return PyErr_SetFromErrno(PyExc_IOError);
    return PyInt_FromSize_t(wbytes);
}

PyDoc_STRVAR(unistd_sysconf__doc__,
"");

/*@null@*/
static PyObject*
unistd_sysconf(/*@unused@*/ PyObject* self, PyObject* args, PyObject* kwds)
{
    int name, res;
    static char *kwlist[] = {"name", NULL};
    if(!PyArg_ParseTupleAndKeywords(args, kwds, "i:sysconf", kwlist, &name))
        return NULL;
    errno = 0;
    res = sysconf(name);
    if (res == -1 && errno)
        return PyErr_SetFromErrno(PyExc_OSError); 
    return PyInt_FromLong(res);
}


static PyMethodDef unistd_methods[] = {
    {"access", (PyCFunction)unistd_access, METH_KEYWORDS, unistd_access__doc__},
    {"alarm", (PyCFunction)unistd_alarm, METH_KEYWORDS, unistd_alarm__doc__},
    {"chdir", (PyCFunction)unistd_chdir, METH_KEYWORDS, unistd_chdir__doc__},
    {"chown", (PyCFunction)unistd_chown, METH_KEYWORDS, unistd_chown__doc__},
    {"close", (PyCFunction)unistd_close, METH_KEYWORDS, unistd_close__doc__},
    {"confstr", (PyCFunction)unistd_confstr, METH_KEYWORDS, unistd_confstr__doc__},
    {"crypt", (PyCFunction)unistd_crypt, METH_KEYWORDS, unistd_crypt__doc__},
    {"ctermid", (PyCFunction)unistd_ctermid, METH_KEYWORDS, unistd_ctermid__doc__},
    {"dup", (PyCFunction)unistd_dup, METH_KEYWORDS, unistd_dup__doc__},
    {"dup2", (PyCFunction)unistd_dup2, METH_KEYWORDS, unistd_dup2__doc__},
    {"encrypt", (PyCFunction)unistd_encrypt, METH_KEYWORDS, unistd_encrypt__doc__},
    /*
    {"execl", (PyCFunction)unistd_execl, METH_KEYWORDS, unistd_execl__doc__},
    {"execle", (PyCFunction)unistd_execle, METH_KEYWORDS, unistd_execle__doc__},
    {"execlp", (PyCFunction)unistd_execlp, METH_KEYWORDS, unistd_execlp__doc__},
    {"execv", (PyCFunction)unistd_execv, METH_KEYWORDS, unistd_execv__doc__},
    {"execve", (PyCFunction)unistd_execve, METH_KEYWORDS, unistd_execve__doc__},
    {"execvp", (PyCFunction)unistd_execvp, METH_KEYWORDS, unistd_execvp__doc__},
    */
    {"_exit", (PyCFunction)unistd__exit, METH_KEYWORDS, unistd__exit__doc__},
    {"fchown", (PyCFunction)unistd_fchown, METH_KEYWORDS, unistd_fchown__doc__},
    {"fchdir", (PyCFunction)unistd_fchdir, METH_KEYWORDS, unistd_fchdir__doc__},
    {"fdatasync", (PyCFunction)unistd_fdatasync, METH_KEYWORDS, unistd_fdatasync__doc__},
    {"fork", (PyCFunction)unistd_fork, METH_KEYWORDS, unistd_fork__doc__},
    {"fpathconf", (PyCFunction)unistd_fpathconf, METH_KEYWORDS, unistd_fpathconf__doc__},
    {"fsync", (PyCFunction)unistd_fsync, METH_KEYWORDS, unistd_fsync__doc__},
    {"ftruncate", (PyCFunction)unistd_ftruncate, METH_KEYWORDS, unistd_ftruncate__doc__},
    {"getcwd", (PyCFunction)unistd_getcwd, METH_KEYWORDS, unistd_getcwd__doc__},
    {"getegid", (PyCFunction)unistd_getegid, METH_KEYWORDS, unistd_getegid__doc__},
    {"geteuid", (PyCFunction)unistd_geteuid, METH_KEYWORDS, unistd_geteuid__doc__},
    {"getgid", (PyCFunction)unistd_getgid, METH_KEYWORDS, unistd_getgid__doc__},
    {"getgroups", (PyCFunction)unistd_getgroups, METH_KEYWORDS, unistd_getgroups__doc__},
    /* {"", (PyCFunction)unistd_, METH_KEYWORDS, unistd___doc__}, */
    {"gethostid", (PyCFunction)unistd_gethostid, METH_KEYWORDS, unistd_gethostid__doc__},
    /* {"gethostname", (PyCFunction)unistd_gethostname, METH_KEYWORDS, unistd_gethostname__doc__}, */
    {"getlogin", (PyCFunction)unistd_getlogin, METH_KEYWORDS, unistd_getlogin__doc__},
    /* {"getopt", (PyCFunction)unistd_getopt, METH_KEYWORDS, unistd_getopt__doc__}, */
    {"getpgid", (PyCFunction)unistd_getpgid, METH_KEYWORDS, unistd_getpgid__doc__},
    {"getpgrp", (PyCFunction)unistd_getpgrp, METH_NOARGS, unistd_getpgrp__doc__},
    {"getpid", (PyCFunction)unistd_getpid, METH_KEYWORDS, unistd_getpid__doc__},
    {"getppid", (PyCFunction)unistd_getppid, METH_KEYWORDS, unistd_getppid__doc__},
    {"getsid", (PyCFunction)unistd_getsid, METH_KEYWORDS, unistd_getsid__doc__},
    {"getuid", (PyCFunction)unistd_getuid, METH_KEYWORDS, unistd_getuid__doc__},
    
    {"isatty", (PyCFunction)unistd_isatty, METH_KEYWORDS, unistd_isatty__doc__},

    {"setgid", (PyCFunction)unistd_setgid, METH_KEYWORDS, unistd_setgid__doc__},
    {"setpgid", (PyCFunction)unistd_setpgid, METH_KEYWORDS, unistd_setpgid__doc__},
    {"setreuid", (PyCFunction)unistd_setreuid, METH_KEYWORDS, unistd_setreuid__doc__},
    {"setregid", (PyCFunction)unistd_setregid, METH_KEYWORDS, unistd_setregid__doc__},
    {"setsid", (PyCFunction)unistd_setsid, METH_KEYWORDS, unistd_setsid__doc__},
    {"setuid", (PyCFunction)unistd_setuid, METH_KEYWORDS, unistd_setuid__doc__},
    {"sysconf", (PyCFunction)unistd_sysconf, METH_KEYWORDS, unistd_sysconf__doc__},
    
    {"nice", (PyCFunction)unistd_nice, METH_KEYWORDS, unistd_nice__doc__},
    {"pathconf", (PyCFunction)unistd_pathconf, METH_KEYWORDS, unistd_pathconf__doc__},
    {"pread", (PyCFunction)unistd_pread, METH_KEYWORDS, unistd_pread__doc__},
    {"pwrite", (PyCFunction)unistd_pwrite, METH_KEYWORDS, unistd_pwrite__doc__},
    {"read", (PyCFunction)unistd_read, METH_KEYWORDS, unistd_read__doc__},
    {"sleep", (PyCFunction)unistd_sleep, METH_KEYWORDS, unistd_sleep__doc__},
    {"vfork", (PyCFunction)unistd_vfork, METH_KEYWORDS, unistd_vfork__doc__},
    {"write", (PyCFunction)unistd_write, METH_KEYWORDS, unistd_write__doc__},
    {"write", (PyCFunction)unistd_write, METH_KEYWORDS, unistd_write__doc__},

    {NULL}
};


PyDoc_STRVAR(unistd__doc__,
"unistd module defines miscellaneous constants and miscellaneous functions\n"
"from the <unistd.h>.\n\n"
"Documentation is a adapted version of pubs.opengroup.org documentation.");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initunistd(void)
{
    PyObject *m;

    m = Py_InitModule3("unistd", unistd_methods, unistd__doc__);

    if(m == NULL)
        return;

    /* MACROS */
#ifdef _POSIX_VERSION
    if(PyModule_AddIntMacro(m, _POSIX_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_VERSION", Py_None))
#endif
        return;

#ifdef _POSIX2_VERSION
    if(PyModule_AddIntMacro(m, _POSIX2_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_VERSION", Py_None))
#endif
        return;

#ifdef _POSIX2_C_VERSION
    if(PyModule_AddIntMacro(m, _POSIX2_C_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_C_VERSION", Py_None))
#endif
        return;

#ifdef _XOPEN_VERSION
    if(PyModule_AddIntMacro(m, _XOPEN_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_VERSION", Py_None))
#endif
        return;

#ifdef _XOPEN_XCU_VERSION
    if(PyModule_AddIntMacro(m, _XOPEN_XCU_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_XCU_VERSION", Py_None))
#endif
        return;

#ifdef _XOPEN_XPG2
    if(PyModule_AddIntMacro(m, _XOPEN_XPG2))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_XPG2", Py_None))
#endif
        return;

#ifdef _XOPEN_XPG3
    if(PyModule_AddIntMacro(m, _XOPEN_XPG3))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_XPG3", Py_None))
#endif
        return;

#ifdef _XOPEN_XPG4
    if(PyModule_AddIntMacro(m, _XOPEN_XPG4))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_XPG4", Py_None))
#endif
        return;

#ifdef _XOPEN_UNIX
    if(PyModule_AddIntMacro(m, _XOPEN_UNIX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_UNIX", Py_None))
#endif
        return;

#ifdef _POSIX_CHOWN_RESTRICTED
    if(PyModule_AddIntMacro(m, _POSIX_CHOWN_RESTRICTED))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_CHOWN_RESTRICTED", Py_None))
#endif
        return;

#ifdef _POSIX_NO_TRUNC
    if(PyModule_AddIntMacro(m, _POSIX_NO_TRUNC))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_NO_TRUNC", Py_None))
#endif
        return;

#ifdef _POSIX_VDISABLE
    if(PyModule_AddIntMacro(m, _POSIX_VDISABLE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_VDISABLE", Py_None))
#endif
        return;

#ifdef _POSIX_SAVED_IDS
    if(PyModule_AddIntMacro(m, _POSIX_SAVED_IDS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_SAVED_IDS", Py_None))
#endif
        return;

#ifdef _POSIX_JOB_CONTROL
    if(PyModule_AddIntMacro(m, _POSIX_JOB_CONTROL))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_JOB_CONTROL", Py_None))
#endif
        return;

#ifdef _POSIX_CHOWN_RESTRICTED
    if(PyModule_AddIntMacro(m, _POSIX_CHOWN_RESTRICTED))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_CHOWN_RESTRICTED", Py_None))
#endif
        return;

#ifdef _POSIX_NO_TRUNC
    if(PyModule_AddIntMacro(m, _POSIX_NO_TRUNC))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_NO_TRUNC", Py_None))
#endif
        return;

#ifdef _POSIX_VDISABLE
    if(PyModule_AddIntMacro(m, _POSIX_VDISABLE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_VDISABLE", Py_None))
#endif
        return;

#ifdef _POSIX_THREADS
    if(PyModule_AddIntMacro(m, _POSIX_THREADS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREADS", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_ATTR_STACKADDR
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_ATTR_STACKADDR))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_ATTR_STACKADDR", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_ATTR_STACKSIZE
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_ATTR_STACKSIZE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_ATTR_STACKSIZE", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_PROCESS_SHARED
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_PROCESS_SHARED))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_PROCESS_SHARED", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_SAFE_FUNCTIONS
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_SAFE_FUNCTIONS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_SAFE_FUNCTIONS", Py_None))
#endif
        return;

#ifdef _POSIX2_C_BIND
    if(PyModule_AddIntMacro(m, _POSIX2_C_BIND))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_C_BIND", Py_None))
#endif
        return;

#ifdef _POSIX2_C_DEV
    if(PyModule_AddIntMacro(m, _POSIX2_C_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_C_DEV", Py_None))
#endif
        return;

#ifdef _POSIX2_CHAR_TERM
    if(PyModule_AddIntMacro(m, _POSIX2_CHAR_TERM))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_CHAR_TERM", Py_None))
#endif
        return;

#ifdef _POSIX2_FORT_DEV
    if(PyModule_AddIntMacro(m, _POSIX2_FORT_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_FORT_DEV", Py_None))
#endif
        return;

#ifdef _POSIX2_FORT_RUN
    if(PyModule_AddIntMacro(m, _POSIX2_FORT_RUN))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_FORT_RUN", Py_None))
#endif
        return;

#ifdef _POSIX2_LOCALEDEF
    if(PyModule_AddIntMacro(m, _POSIX2_LOCALEDEF))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_LOCALEDEF", Py_None))
#endif
        return;

#ifdef _POSIX2_SW_DEV
    if(PyModule_AddIntMacro(m, _POSIX2_SW_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_SW_DEV", Py_None))
#endif
        return;

#ifdef _POSIX2_UPE
    if(PyModule_AddIntMacro(m, _POSIX2_UPE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX2_UPE", Py_None))
#endif
        return;

#ifdef _XOPEN_CRYPT
    if(PyModule_AddIntMacro(m, _XOPEN_CRYPT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_CRYPT", Py_None))
#endif
        return;

#ifdef _XOPEN_ENH_I18N
    if(PyModule_AddIntMacro(m, _XOPEN_ENH_I18N))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_ENH_I18N", Py_None))
#endif
        return;

#ifdef _XOPEN_LEGACY
    if(PyModule_AddIntMacro(m, _XOPEN_LEGACY))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_LEGACY", Py_None))
#endif
        return;

#ifdef _XOPEN_REALTIME
    if(PyModule_AddIntMacro(m, _XOPEN_REALTIME))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_REALTIME", Py_None))
#endif
        return;

#ifdef _XOPEN_REALTIME_THREADS
    if(PyModule_AddIntMacro(m, _XOPEN_REALTIME_THREADS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_REALTIME_THREADS", Py_None))
#endif
        return;

#ifdef _XOPEN_SHM
    if(PyModule_AddIntMacro(m, _XOPEN_SHM))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XOPEN_SHM", Py_None))
#endif
        return;

#ifdef _XBS5_ILP32_OFF32
    if(PyModule_AddIntMacro(m, _XBS5_ILP32_OFF32))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XBS5_ILP32_OFF32", Py_None))
#endif
        return;

#ifdef _XBS5_ILP32_OFFBIG
    if(PyModule_AddIntMacro(m, _XBS5_ILP32_OFFBIG))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XBS5_ILP32_OFFBIG", Py_None))
#endif
        return;

#ifdef _XBS5_LP64_OFF64
    if(PyModule_AddIntMacro(m, _XBS5_LP64_OFF64))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XBS5_LP64_OFF64", Py_None))
#endif
        return;

#ifdef _XBS5_LPBIG_OFFBIG
    if(PyModule_AddIntMacro(m, _XBS5_LPBIG_OFFBIG))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_XBS5_LPBIG_OFFBIG", Py_None))
#endif
        return;

#ifdef _POSIX_ASYNCHRONOUS_IO
    if(PyModule_AddIntMacro(m, _POSIX_ASYNCHRONOUS_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_ASYNCHRONOUS_IO", Py_None))
#endif
        return;

#ifdef _POSIX_MEMLOCK
    if(PyModule_AddIntMacro(m, _POSIX_MEMLOCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_MEMLOCK", Py_None))
#endif
        return;

#ifdef _POSIX_MEMLOCK_RANGE
    if(PyModule_AddIntMacro(m, _POSIX_MEMLOCK_RANGE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_MEMLOCK_RANGE", Py_None))
#endif
        return;

#ifdef _POSIX_MESSAGE_PASSING
    if(PyModule_AddIntMacro(m, _POSIX_MESSAGE_PASSING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_MESSAGE_PASSING", Py_None))
#endif
        return;

#ifdef _POSIX_PRIORITY_SCHEDULING
    if(PyModule_AddIntMacro(m, _POSIX_PRIORITY_SCHEDULING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_PRIORITY_SCHEDULING", Py_None))
#endif
        return;

#ifdef _POSIX_REALTIME_SIGNALS
    if(PyModule_AddIntMacro(m, _POSIX_REALTIME_SIGNALS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_REALTIME_SIGNALS", Py_None))
#endif
        return;

#ifdef _POSIX_SEMAPHORES
    if(PyModule_AddIntMacro(m, _POSIX_SEMAPHORES))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_SEMAPHORES", Py_None))
#endif
        return;

#ifdef _POSIX_SHARED_MEMORY_OBJECTS
    if(PyModule_AddIntMacro(m, _POSIX_SHARED_MEMORY_OBJECTS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_SHARED_MEMORY_OBJECTS", Py_None))
#endif
        return;

#ifdef _POSIX_SYNCHRONIZED_IO
    if(PyModule_AddIntMacro(m, _POSIX_SYNCHRONIZED_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_SYNCHRONIZED_IO", Py_None))
#endif
        return;

#ifdef _POSIX_TIMERS
    if(PyModule_AddIntMacro(m, _POSIX_TIMERS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_TIMERS", Py_None))
#endif
        return;

#ifdef _POSIX_FSYNC
    if(PyModule_AddIntMacro(m, _POSIX_FSYNC))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_FSYNC", Py_None))
#endif
        return;

#ifdef _POSIX_MAPPED_FILES
    if(PyModule_AddIntMacro(m, _POSIX_MAPPED_FILES))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_MAPPED_FILES", Py_None))
#endif
        return;

#ifdef _POSIX_MEMORY_PROTECTION
    if(PyModule_AddIntMacro(m, _POSIX_MEMORY_PROTECTION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_MEMORY_PROTECTION", Py_None))
#endif
        return;

#ifdef _POSIX_PRIORITIZED_IO
    if(PyModule_AddIntMacro(m, _POSIX_PRIORITIZED_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_PRIORITIZED_IO", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_PRIORITY_SCHEDULING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_PRIORITY_SCHEDULING", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_PRIO_INHERIT
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_PRIO_INHERIT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_PRIO_INHERIT", Py_None))
#endif
        return;

#ifdef _POSIX_THREAD_PRIO_PROTECT
    if(PyModule_AddIntMacro(m, _POSIX_THREAD_PRIO_PROTECT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_THREAD_PRIO_PROTECT", Py_None))
#endif
        return;

#ifdef _POSIX_ASYNC_IO
    if(PyModule_AddIntMacro(m, _POSIX_ASYNC_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_ASYNC_IO", Py_None))
#endif
        return;

#ifdef _POSIX_PRIO_IO
    if(PyModule_AddIntMacro(m, _POSIX_PRIO_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_PRIO_IO", Py_None))
#endif
        return;

#ifdef _POSIX_SYNC_IO
    if(PyModule_AddIntMacro(m, _POSIX_SYNC_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_POSIX_SYNC_IO", Py_None))
#endif
        return;

/*
#ifdef NULL
    if(PyModule_AddIntMacro(m, NULL))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "NULL", Py_None))
#endif
        return;
*/

#ifdef R_OK
    if(PyModule_AddIntMacro(m, R_OK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "R_OK", Py_None))
#endif
        return;

#ifdef W_OK
    if(PyModule_AddIntMacro(m, W_OK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "W_OK", Py_None))
#endif
        return;

#ifdef X_OK
    if(PyModule_AddIntMacro(m, X_OK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "X_OK", Py_None))
#endif
        return;

#ifdef F_OK
    if(PyModule_AddIntMacro(m, F_OK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "F_OK", Py_None))
#endif
        return;

#ifdef _CS_PATH
    if(PyModule_AddIntMacro(m, _CS_PATH))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_PATH", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFF32_CFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFF32_CFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFF32_CFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFF32_LDFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFF32_LDFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFF32_LDFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFF32_LIBS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFF32_LIBS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFF32_LIBS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFF32_LINTFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFF32_LINTFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFF32_LINTFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFFBIG_CFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFFBIG_CFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFFBIG_CFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFFBIG_LDFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFFBIG_LDFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFFBIG_LDFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFFBIG_LIBS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFFBIG_LIBS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFFBIG_LIBS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_ILP32_OFFBIG_LINTFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_ILP32_OFFBIG_LINTFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_ILP32_OFFBIG_LINTFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LP64_OFF64_CFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LP64_OFF64_CFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LP64_OFF64_CFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LP64_OFF64_LDFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LP64_OFF64_LDFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LP64_OFF64_LDFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LP64_OFF64_LIBS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LP64_OFF64_LIBS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LP64_OFF64_LIBS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LP64_OFF64_LINTFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LP64_OFF64_LINTFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LP64_OFF64_LINTFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LPBIG_OFFBIG_CFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LPBIG_OFFBIG_CFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LPBIG_OFFBIG_CFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LPBIG_OFFBIG_LDFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LPBIG_OFFBIG_LDFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LPBIG_OFFBIG_LDFLAGS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LPBIG_OFFBIG_LIBS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LPBIG_OFFBIG_LIBS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LPBIG_OFFBIG_LIBS", Py_None))
#endif
        return;

#ifdef _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS
    if(PyModule_AddIntMacro(m, _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS", Py_None))
#endif
        return;

#ifdef SEEK_SET
    if(PyModule_AddIntMacro(m, SEEK_SET))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "SEEK_SET", Py_None))
#endif
        return;

#ifdef SEEK_CUR
    if(PyModule_AddIntMacro(m, SEEK_CUR))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "SEEK_CUR", Py_None))
#endif
        return;

#ifdef SEEK_END
    if(PyModule_AddIntMacro(m, SEEK_END))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "SEEK_END", Py_None))
#endif
        return;

#ifdef _SC_2_C_BIND
    if(PyModule_AddIntMacro(m, _SC_2_C_BIND))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_C_BIND", Py_None))
#endif
        return;

#ifdef _SC_2_C_DEV
    if(PyModule_AddIntMacro(m, _SC_2_C_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_C_DEV", Py_None))
#endif
        return;

#ifdef _SC_2_C_VERSION
    if(PyModule_AddIntMacro(m, _SC_2_C_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_C_VERSION", Py_None))
#endif
        return;

#ifdef _SC_2_FORT_DEV
    if(PyModule_AddIntMacro(m, _SC_2_FORT_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_FORT_DEV", Py_None))
#endif
        return;

#ifdef _SC_2_FORT_RUN
    if(PyModule_AddIntMacro(m, _SC_2_FORT_RUN))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_FORT_RUN", Py_None))
#endif
        return;

#ifdef _SC_2_LOCALEDEF
    if(PyModule_AddIntMacro(m, _SC_2_LOCALEDEF))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_LOCALEDEF", Py_None))
#endif
        return;

#ifdef _SC_2_SW_DEV
    if(PyModule_AddIntMacro(m, _SC_2_SW_DEV))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_SW_DEV", Py_None))
#endif
        return;

#ifdef _SC_2_UPE
    if(PyModule_AddIntMacro(m, _SC_2_UPE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_UPE", Py_None))
#endif
        return;

#ifdef _SC_2_VERSION
    if(PyModule_AddIntMacro(m, _SC_2_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_2_VERSION", Py_None))
#endif
        return;

#ifdef _SC_ARG_MAX
    if(PyModule_AddIntMacro(m, _SC_ARG_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_ARG_MAX", Py_None))
#endif
        return;

#ifdef _SC_AIO_LISTIO_MAX
    if(PyModule_AddIntMacro(m, _SC_AIO_LISTIO_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_AIO_LISTIO_MAX", Py_None))
#endif
        return;

#ifdef _SC_AIO_MAX
    if(PyModule_AddIntMacro(m, _SC_AIO_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_AIO_MAX", Py_None))
#endif
        return;

#ifdef _SC_AIO_PRIO_DELTA_MAX
    if(PyModule_AddIntMacro(m, _SC_AIO_PRIO_DELTA_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_AIO_PRIO_DELTA_MAX", Py_None))
#endif
        return;

#ifdef _SC_ASYNCHRONOUS_IO
    if(PyModule_AddIntMacro(m, _SC_ASYNCHRONOUS_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_ASYNCHRONOUS_IO", Py_None))
#endif
        return;

#ifdef _SC_ATEXIT_MAX
    if(PyModule_AddIntMacro(m, _SC_ATEXIT_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_ATEXIT_MAX", Py_None))
#endif
        return;

#ifdef _SC_BC_BASE_MAX
    if(PyModule_AddIntMacro(m, _SC_BC_BASE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_BC_BASE_MAX", Py_None))
#endif
        return;

#ifdef _SC_BC_DIM_MAX
    if(PyModule_AddIntMacro(m, _SC_BC_DIM_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_BC_DIM_MAX", Py_None))
#endif
        return;

#ifdef _SC_BC_SCALE_MAX
    if(PyModule_AddIntMacro(m, _SC_BC_SCALE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_BC_SCALE_MAX", Py_None))
#endif
        return;

#ifdef _SC_BC_STRING_MAX
    if(PyModule_AddIntMacro(m, _SC_BC_STRING_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_BC_STRING_MAX", Py_None))
#endif
        return;

#ifdef _SC_CHILD_MAX
    if(PyModule_AddIntMacro(m, _SC_CHILD_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_CHILD_MAX", Py_None))
#endif
        return;

#ifdef _SC_CLK_TCK
    if(PyModule_AddIntMacro(m, _SC_CLK_TCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_CLK_TCK", Py_None))
#endif
        return;

#ifdef _SC_COLL_WEIGHTS_MAX
    if(PyModule_AddIntMacro(m, _SC_COLL_WEIGHTS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_COLL_WEIGHTS_MAX", Py_None))
#endif
        return;

#ifdef _SC_DELAYTIMER_MAX
    if(PyModule_AddIntMacro(m, _SC_DELAYTIMER_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_DELAYTIMER_MAX", Py_None))
#endif
        return;

#ifdef _SC_EXPR_NEST_MAX
    if(PyModule_AddIntMacro(m, _SC_EXPR_NEST_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_EXPR_NEST_MAX", Py_None))
#endif
        return;

#ifdef _SC_FSYNC
    if(PyModule_AddIntMacro(m, _SC_FSYNC))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_FSYNC", Py_None))
#endif
        return;

#ifdef _SC_GETGR_R_SIZE_MAX
    if(PyModule_AddIntMacro(m, _SC_GETGR_R_SIZE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_GETGR_R_SIZE_MAX", Py_None))
#endif
        return;

#ifdef _SC_GETPW_R_SIZE_MAX
    if(PyModule_AddIntMacro(m, _SC_GETPW_R_SIZE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_GETPW_R_SIZE_MAX", Py_None))
#endif
        return;

#ifdef _SC_IOV_MAX
    if(PyModule_AddIntMacro(m, _SC_IOV_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_IOV_MAX", Py_None))
#endif
        return;

#ifdef _SC_JOB_CONTROL
    if(PyModule_AddIntMacro(m, _SC_JOB_CONTROL))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_JOB_CONTROL", Py_None))
#endif
        return;

#ifdef _SC_LINE_MAX
    if(PyModule_AddIntMacro(m, _SC_LINE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_LINE_MAX", Py_None))
#endif
        return;

#ifdef _SC_LOGIN_NAME_MAX
    if(PyModule_AddIntMacro(m, _SC_LOGIN_NAME_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_LOGIN_NAME_MAX", Py_None))
#endif
        return;

#ifdef _SC_MAPPED_FILES
    if(PyModule_AddIntMacro(m, _SC_MAPPED_FILES))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MAPPED_FILES", Py_None))
#endif
        return;

#ifdef _SC_MEMLOCK
    if(PyModule_AddIntMacro(m, _SC_MEMLOCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MEMLOCK", Py_None))
#endif
        return;

#ifdef _SC_MEMLOCK_RANGE
    if(PyModule_AddIntMacro(m, _SC_MEMLOCK_RANGE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MEMLOCK_RANGE", Py_None))
#endif
        return;

#ifdef _SC_MEMORY_PROTECTION
    if(PyModule_AddIntMacro(m, _SC_MEMORY_PROTECTION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MEMORY_PROTECTION", Py_None))
#endif
        return;

#ifdef _SC_MESSAGE_PASSING
    if(PyModule_AddIntMacro(m, _SC_MESSAGE_PASSING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MESSAGE_PASSING", Py_None))
#endif
        return;

#ifdef _SC_MQ_OPEN_MAX
    if(PyModule_AddIntMacro(m, _SC_MQ_OPEN_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MQ_OPEN_MAX", Py_None))
#endif
        return;

#ifdef _SC_MQ_PRIO_MAX
    if(PyModule_AddIntMacro(m, _SC_MQ_PRIO_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_MQ_PRIO_MAX", Py_None))
#endif
        return;

#ifdef _SC_NGROUPS_MAX
    if(PyModule_AddIntMacro(m, _SC_NGROUPS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_NGROUPS_MAX", Py_None))
#endif
        return;

#ifdef _SC_OPEN_MAX
    if(PyModule_AddIntMacro(m, _SC_OPEN_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_OPEN_MAX", Py_None))
#endif
        return;

#ifdef _SC_PAGESIZE
    if(PyModule_AddIntMacro(m, _SC_PAGESIZE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_PAGESIZE", Py_None))
#endif
        return;

#ifdef _SC_PAGE_SIZE
    if(PyModule_AddIntMacro(m, _SC_PAGE_SIZE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_PAGE_SIZE", Py_None))
#endif
        return;

#ifdef _SC_PASS_MAX
    if(PyModule_AddIntMacro(m, _SC_PASS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_PASS_MAX", Py_None))
#endif
        return;

#ifdef _SC_PRIORITIZED_IO
    if(PyModule_AddIntMacro(m, _SC_PRIORITIZED_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_PRIORITIZED_IO", Py_None))
#endif
        return;

#ifdef _SC_PRIORITY_SCHEDULING
    if(PyModule_AddIntMacro(m, _SC_PRIORITY_SCHEDULING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_PRIORITY_SCHEDULING", Py_None))
#endif
        return;

#ifdef _SC_RE_DUP_MAX
    if(PyModule_AddIntMacro(m, _SC_RE_DUP_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_RE_DUP_MAX", Py_None))
#endif
        return;

#ifdef _SC_REALTIME_SIGNALS
    if(PyModule_AddIntMacro(m, _SC_REALTIME_SIGNALS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_REALTIME_SIGNALS", Py_None))
#endif
        return;

#ifdef _SC_RTSIG_MAX
    if(PyModule_AddIntMacro(m, _SC_RTSIG_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_RTSIG_MAX", Py_None))
#endif
        return;

#ifdef _SC_SAVED_IDS
    if(PyModule_AddIntMacro(m, _SC_SAVED_IDS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SAVED_IDS", Py_None))
#endif
        return;

#ifdef _SC_SEMAPHORES
    if(PyModule_AddIntMacro(m, _SC_SEMAPHORES))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SEMAPHORES", Py_None))
#endif
        return;

#ifdef _SC_SEM_NSEMS_MAX
    if(PyModule_AddIntMacro(m, _SC_SEM_NSEMS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SEM_NSEMS_MAX", Py_None))
#endif
        return;

#ifdef _SC_SEM_VALUE_MAX
    if(PyModule_AddIntMacro(m, _SC_SEM_VALUE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SEM_VALUE_MAX", Py_None))
#endif
        return;

#ifdef _SC_SHARED_MEMORY_OBJECTS
    if(PyModule_AddIntMacro(m, _SC_SHARED_MEMORY_OBJECTS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SHARED_MEMORY_OBJECTS", Py_None))
#endif
        return;

#ifdef _SC_SIGQUEUE_MAX
    if(PyModule_AddIntMacro(m, _SC_SIGQUEUE_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SIGQUEUE_MAX", Py_None))
#endif
        return;

#ifdef _SC_STREAM_MAX
    if(PyModule_AddIntMacro(m, _SC_STREAM_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_STREAM_MAX", Py_None))
#endif
        return;

#ifdef _SC_SYNCHRONIZED_IO
    if(PyModule_AddIntMacro(m, _SC_SYNCHRONIZED_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_SYNCHRONIZED_IO", Py_None))
#endif
        return;

#ifdef _SC_THREADS
    if(PyModule_AddIntMacro(m, _SC_THREADS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREADS", Py_None))
#endif
        return;

#ifdef _SC_THREAD_ATTR_STACKADDR
    if(PyModule_AddIntMacro(m, _SC_THREAD_ATTR_STACKADDR))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_ATTR_STACKADDR", Py_None))
#endif
        return;

#ifdef _SC_THREAD_ATTR_STACKSIZE
    if(PyModule_AddIntMacro(m, _SC_THREAD_ATTR_STACKSIZE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_ATTR_STACKSIZE", Py_None))
#endif
        return;

#ifdef _SC_THREAD_DESTRUCTOR_ITERATIONS
    if(PyModule_AddIntMacro(m, _SC_THREAD_DESTRUCTOR_ITERATIONS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_DESTRUCTOR_ITERATIONS", Py_None))
#endif
        return;

#ifdef _SC_THREAD_KEYS_MAX
    if(PyModule_AddIntMacro(m, _SC_THREAD_KEYS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_KEYS_MAX", Py_None))
#endif
        return;

#ifdef _SC_THREAD_PRIORITY_SCHEDULING
    if(PyModule_AddIntMacro(m, _SC_THREAD_PRIORITY_SCHEDULING))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_PRIORITY_SCHEDULING", Py_None))
#endif
        return;

#ifdef _SC_THREAD_PRIO_INHERIT
    if(PyModule_AddIntMacro(m, _SC_THREAD_PRIO_INHERIT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_PRIO_INHERIT", Py_None))
#endif
        return;

#ifdef _SC_THREAD_PRIO_PROTECT
    if(PyModule_AddIntMacro(m, _SC_THREAD_PRIO_PROTECT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_PRIO_PROTECT", Py_None))
#endif
        return;

#ifdef _SC_THREAD_PROCESS_SHARED
    if(PyModule_AddIntMacro(m, _SC_THREAD_PROCESS_SHARED))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_PROCESS_SHARED", Py_None))
#endif
        return;

#ifdef _SC_THREAD_SAFE_FUNCTIONS
    if(PyModule_AddIntMacro(m, _SC_THREAD_SAFE_FUNCTIONS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_SAFE_FUNCTIONS", Py_None))
#endif
        return;

#ifdef _SC_THREAD_STACK_MIN
    if(PyModule_AddIntMacro(m, _SC_THREAD_STACK_MIN))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_STACK_MIN", Py_None))
#endif
        return;

#ifdef _SC_THREAD_THREADS_MAX
    if(PyModule_AddIntMacro(m, _SC_THREAD_THREADS_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_THREAD_THREADS_MAX", Py_None))
#endif
        return;

#ifdef _SC_TIMERS
    if(PyModule_AddIntMacro(m, _SC_TIMERS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_TIMERS", Py_None))
#endif
        return;

#ifdef _SC_TIMER_MAX
    if(PyModule_AddIntMacro(m, _SC_TIMER_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_TIMER_MAX", Py_None))
#endif
        return;

#ifdef _SC_TTY_NAME_MAX
    if(PyModule_AddIntMacro(m, _SC_TTY_NAME_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_TTY_NAME_MAX", Py_None))
#endif
        return;

#ifdef _SC_TZNAME_MAX
    if(PyModule_AddIntMacro(m, _SC_TZNAME_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_TZNAME_MAX", Py_None))
#endif
        return;

#ifdef _SC_VERSION
    if(PyModule_AddIntMacro(m, _SC_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_VERSION", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_VERSION
    if(PyModule_AddIntMacro(m, _SC_XOPEN_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_VERSION", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_CRYPT
    if(PyModule_AddIntMacro(m, _SC_XOPEN_CRYPT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_CRYPT", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_ENH_I18N
    if(PyModule_AddIntMacro(m, _SC_XOPEN_ENH_I18N))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_ENH_I18N", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_SHM
    if(PyModule_AddIntMacro(m, _SC_XOPEN_SHM))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_SHM", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_UNIX
    if(PyModule_AddIntMacro(m, _SC_XOPEN_UNIX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_UNIX", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_XCU_VERSION
    if(PyModule_AddIntMacro(m, _SC_XOPEN_XCU_VERSION))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_XCU_VERSION", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_LEGACY
    if(PyModule_AddIntMacro(m, _SC_XOPEN_LEGACY))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_LEGACY", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_REALTIME
    if(PyModule_AddIntMacro(m, _SC_XOPEN_REALTIME))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_REALTIME", Py_None))
#endif
        return;

#ifdef _SC_XOPEN_REALTIME_THREADS
    if(PyModule_AddIntMacro(m, _SC_XOPEN_REALTIME_THREADS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XOPEN_REALTIME_THREADS", Py_None))
#endif
        return;

#ifdef _SC_XBS5_ILP32_OFF32
    if(PyModule_AddIntMacro(m, _SC_XBS5_ILP32_OFF32))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XBS5_ILP32_OFF32", Py_None))
#endif
        return;

#ifdef _SC_XBS5_ILP32_OFFBIG
    if(PyModule_AddIntMacro(m, _SC_XBS5_ILP32_OFFBIG))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XBS5_ILP32_OFFBIG", Py_None))
#endif
        return;

#ifdef _SC_XBS5_LP64_OFF64
    if(PyModule_AddIntMacro(m, _SC_XBS5_LP64_OFF64))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XBS5_LP64_OFF64", Py_None))
#endif
        return;

#ifdef _SC_XBS5_LPBIG_OFFBIG
    if(PyModule_AddIntMacro(m, _SC_XBS5_LPBIG_OFFBIG))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_SC_XBS5_LPBIG_OFFBIG", Py_None))
#endif
        return;

#ifdef F_LOCK
    if(PyModule_AddIntMacro(m, F_LOCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "F_LOCK", Py_None))
#endif
        return;

#ifdef F_ULOCK
    if(PyModule_AddIntMacro(m, F_ULOCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "F_ULOCK", Py_None))
#endif
        return;

#ifdef F_TEST
    if(PyModule_AddIntMacro(m, F_TEST))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "F_TEST", Py_None))
#endif
        return;

#ifdef F_TLOCK
    if(PyModule_AddIntMacro(m, F_TLOCK))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "F_TLOCK", Py_None))
#endif
        return;

#ifdef _PC_ASYNC_IO
    if(PyModule_AddIntMacro(m, _PC_ASYNC_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_ASYNC_IO", Py_None))
#endif
        return;

#ifdef _PC_CHOWN_RESTRICTED
    if(PyModule_AddIntMacro(m, _PC_CHOWN_RESTRICTED))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_CHOWN_RESTRICTED", Py_None))
#endif
        return;

#ifdef _PC_FILESIZEBITS
    if(PyModule_AddIntMacro(m, _PC_FILESIZEBITS))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_FILESIZEBITS", Py_None))
#endif
        return;

#ifdef _PC_LINK_MAX
    if(PyModule_AddIntMacro(m, _PC_LINK_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_LINK_MAX", Py_None))
#endif
        return;

#ifdef _PC_MAX_CANON
    if(PyModule_AddIntMacro(m, _PC_MAX_CANON))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_MAX_CANON", Py_None))
#endif
        return;

#ifdef _PC_MAX_INPUT
    if(PyModule_AddIntMacro(m, _PC_MAX_INPUT))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_MAX_INPUT", Py_None))
#endif
        return;

#ifdef _PC_NAME_MAX
    if(PyModule_AddIntMacro(m, _PC_NAME_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_NAME_MAX", Py_None))
#endif
        return;

#ifdef _PC_NO_TRUNC
    if(PyModule_AddIntMacro(m, _PC_NO_TRUNC))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_NO_TRUNC", Py_None))
#endif
        return;

#ifdef _PC_PATH_MAX
    if(PyModule_AddIntMacro(m, _PC_PATH_MAX))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_PATH_MAX", Py_None))
#endif
        return;

#ifdef _PC_PIPE_BUF
    if(PyModule_AddIntMacro(m, _PC_PIPE_BUF))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_PIPE_BUF", Py_None))
#endif
        return;

#ifdef _PC_PRIO_IO
    if(PyModule_AddIntMacro(m, _PC_PRIO_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_PRIO_IO", Py_None))
#endif
        return;

#ifdef _PC_SYNC_IO
    if(PyModule_AddIntMacro(m, _PC_SYNC_IO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_SYNC_IO", Py_None))
#endif
        return;

#ifdef _PC_VDISABLE
    if(PyModule_AddIntMacro(m, _PC_VDISABLE))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "_PC_VDISABLE", Py_None))
#endif
        return;

#ifdef STDIN_FILENO
    if(PyModule_AddIntMacro(m, STDIN_FILENO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "STDIN_FILENO", Py_None))
#endif
        return;

#ifdef STDOUT_FILENO
    if(PyModule_AddIntMacro(m, STDOUT_FILENO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "STDOUT_FILENO", Py_None))
#endif
        return;

#ifdef STDERR_FILENO
    if(PyModule_AddIntMacro(m, STDERR_FILENO))
#else
    Py_INCREF(Py_None);
    if(PyModule_AddObject(m, "STDERR_FILENO", Py_None))
#endif
        return;

}
