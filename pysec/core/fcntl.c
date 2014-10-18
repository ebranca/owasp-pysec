#include <Python.h>
#include <fcntl.h>


PyDoc_STRVAR(fcntl_creat__doc__,
"");

static PyObject*
fcntl_creat(PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int mode, fd;
    /* TODO add mode */
    static char *kwlist[] = {"fd", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "si:creat", kwlist, &path, &mode))
        return NULL;

    fd = creat(path, mode);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(fd);
}

PyDoc_STRVAR(fcntl_open__doc__,
"");

static PyObject*
fcntl_open(PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int flags, fd, mode=0644;
    static char *kwlist[] = {"path", "flags", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "si|i:open", kwlist, &path, &flags, &mode))
        return NULL;

    fd = open(path, flags, mode);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(fd);
}

PyDoc_STRVAR(fcntl_openat__doc__,
"");

static PyObject*
fcntl_openat(PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int flags, fd, mode = 0644;
    static char *kwlist[] = {"dirfd", "path", "flags", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "isi|i:openat", kwlist, &fd, &path, &flags, &mode))
        return NULL;

    fd = openat(fd, path, flags, mode);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(fd);
}

PyDoc_STRVAR(fcntl_fcntl__doc__,
"");

static PyObject*
fcntl_fcntl(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fildes, cmd, arg = 0, ret;
    static char *kwlist[] = {"fildes", "cmd", "arg", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ii|i:open", kwlist, &fildes, &cmd, &arg))
        return NULL;

    ret = fcntl(fildes, cmd, arg);
    if (ret < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(ret);
}

static PyMethodDef fcntl_methods[] = {
    {"open", (PyCFunction)fcntl_open, METH_KEYWORDS, fcntl_open__doc__},
    {"openat", (PyCFunction)fcntl_openat, METH_KEYWORDS, fcntl_openat__doc__},
    {"creat", (PyCFunction)fcntl_creat, METH_KEYWORDS, fcntl_creat__doc__},
    {"fcntl", (PyCFunction)fcntl_fcntl, METH_KEYWORDS, fcntl_fcntl__doc__},
    { NULL } /* sentinel */
};

PyDoc_STRVAR(fcntl__doc__,
"Library for file control options.");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initfcntl(void)
{
    PyObject *m;

    m = Py_InitModule3("fcntl", fcntl_methods, fcntl__doc__);

    if(m == NULL)
        return;

    if(PyModule_AddIntMacro(m, F_DUPFD))
        return;

    if(PyModule_AddIntMacro(m, F_GETFD))
        return;

    if(PyModule_AddIntMacro(m, F_SETFD))
        return;

    if(PyModule_AddIntMacro(m, F_GETFL))
        return;

    if(PyModule_AddIntMacro(m, F_SETFL))
        return;

    if(PyModule_AddIntMacro(m, F_GETLK))
        return;

    if(PyModule_AddIntMacro(m, F_SETLK))
        return;

    if(PyModule_AddIntMacro(m, F_SETLKW))
        return;

    if(PyModule_AddIntMacro(m, FD_CLOEXEC))
        return;

    if(PyModule_AddIntMacro(m, F_RDLCK))
        return;

    if(PyModule_AddIntMacro(m, F_UNLCK))
        return;

    if(PyModule_AddIntMacro(m, F_WRLCK))
        return;

    if(PyModule_AddIntMacro(m, O_CREAT))
        return;

    if(PyModule_AddIntMacro(m, O_DIRECTORY))
        return;

    if(PyModule_AddIntMacro(m, O_EXCL))
        return;

    if(PyModule_AddIntMacro(m, O_NOCTTY))
        return;

    if(PyModule_AddIntMacro(m, O_TRUNC))
        return;

    if(PyModule_AddIntMacro(m, O_APPEND))
        return;

    if(PyModule_AddIntMacro(m, O_DSYNC))
        return;

    if(PyModule_AddIntMacro(m, O_NONBLOCK))
        return;

    if(PyModule_AddIntMacro(m, O_RSYNC))
        return;

    if(PyModule_AddIntMacro(m, O_SYNC))
        return;

    if(PyModule_AddIntMacro(m, O_ACCMODE))
        return;

    if(PyModule_AddIntMacro(m, O_RDONLY))
        return;

    if(PyModule_AddIntMacro(m, O_RDWR))
        return;

    if(PyModule_AddIntMacro(m, O_WRONLY))
        return;
}
