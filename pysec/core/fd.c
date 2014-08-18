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
#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

PyDoc_STRVAR(fd_get_inheritable__doc__,
"");

static PyObject*
fd_get_inheritable( PyObject* self, PyObject* args, PyObject* kwds )
{
    int fd=0;
    static char *kwlist[] = {"fd", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &fd))
        return NULL;

    int flags;
    flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyBool_FromLong(!(flags & FD_CLOEXEC));
}

PyDoc_STRVAR(fd_set_inheritable__doc__,
"");

static PyObject*
fd_set_inheritable( PyObject* self, PyObject* args, PyObject* kwds )
{
    int fd=-1;
    int inheritable = 0;
    static char *kwlist[] = {"fd", "inheritable", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i|i", kwlist, &fd, &inheritable))
        return NULL;
   
#if defined(HAVE_SYS_IOCTL_H) && defined(FIOCLEX) && defined(FIONCLEX)
    int request;
    int err;
 
    if (inheritable > 0){
        request = FIONCLEX;
    }else{
        request = FIOCLEX;
    }
    err = ioctl(fd, request, NULL);
    if (err) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    Py_RETURN_TRUE;
#else
    int flags;
    int res;
    
    flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    if (inheritable > 0){
        flags &= ~FD_CLOEXEC;
    }
    else{
        flags |= FD_CLOEXEC;
    }
    res = fcntl(fd, F_SETFD, flags);
    if (res < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    Py_RETURN_TRUE;
#endif
}

static PyMethodDef fd_methods[] = {
    {"get_inheritable", (PyCFunction)fd_get_inheritable, METH_VARARGS| METH_KEYWORDS, fd_get_inheritable__doc__},
    {"set_inheritable", (PyCFunction)fd_set_inheritable, METH_VARARGS| METH_KEYWORDS, fd_set_inheritable__doc__},
    {NULL, NULL, 0 ,NULL}
};

PyDoc_STRVAR(fd__doc__,
"fd module defined miscellaneous constants and function about file descriptor\n\n");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initfd(void){
    PyObject *m = Py_InitModule3("fd", fd_methods, fd__doc__);
    if (m == NULL){
        return;
    }
}
