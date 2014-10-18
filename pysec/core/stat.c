#include "Python.h"
#include "sys/stat.h"

PyDoc_STRVAR(stat_mkdir__doc__,
"");

static PyObject*
stat_mkdir(PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int fd, mode = 0755;
    static char *kwlist[] = {"path", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i:mkdir", kwlist, &path, &mode))
        return NULL;

    fd = mkdir(path, mode);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(fd);
}


PyDoc_STRVAR(stat_mkfifo__doc__,
"");

static PyObject*
stat_mkfifo(PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int fd, mode = 0644;
    static char *kwlist[] = {"path", "mode", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|i:mkfifo", kwlist, &path, &mode))
        return NULL;

    fd = mkfifo(path, mode);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    return PyInt_FromLong(fd);
}


static PyMethodDef stat_methods[] = {
    {"mkdir", (PyCFunction)stat_mkdir, METH_KEYWORDS, stat_mkdir__doc__},
    {"mkfifo", (PyCFunction)stat_mkfifo, METH_KEYWORDS, stat_mkfifo__doc__},
    { NULL } /* sentinel */
};

PyDoc_STRVAR(stat__doc__,
"");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initstat(void)
{
    PyObject *m;

    m = Py_InitModule3("stat", stat_methods, stat__doc__);

    if(m == NULL)
        return;
}
