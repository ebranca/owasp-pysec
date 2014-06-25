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

#include <dirent.h>
#include <fcntl.h>


PyDoc_STRVAR(dirent_opendir__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
dirent_opendir(/*@unused@*/ PyObject* self, PyObject* args, PyObject* kwds)
{
    char *path;
    int fd;
    static char *kwlist[] = {"path", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:opendir", kwlist, &path)) {
        return NULL;
    }
    fd = open(path, O_RDONLY|O_DIRECTORY);
    if (fd == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    return PyInt_FromLong(fd);
}

PyDoc_STRVAR(dirent_readdir__doc__,
"");
/* TODO - doc */

/*@null@*/
static PyObject*
dirent_readdir(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, err, name_len;
    char d_name[NAME_MAX], *name_end;
    DIR *dirp;
    struct dirent *entry;
    PyObject *list, *tuple, *ino, *name;
    static char *kwlist[] = {"fd", NULL};

    ino = name = tuple = list = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:readdir", kwlist, &fd)) {
        return NULL;
    }

    fd = dup(fd);
    if (fd == -1) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    dirp = fdopendir(fd);
    if (dirp == NULL) {
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    /* list with directory's entries */
    list = PyList_New(0);
    if (list == NULL) {
        return NULL;
    }

    do {
        errno = 0;
        entry = readdir(dirp);
        if (entry) {
            /* get entry's inode */
            ino = PyInt_FromLong(entry->d_ino);
            if (!ino) {
                goto error;
            }
            /* get entry's name */
            name_end = (char *)memccpy(d_name, entry->d_name, 0, NAME_MAX);
            if (name_end == NULL) {
                name = PyString_FromStringAndSize(d_name, NAME_MAX);
            }
            else {
                name = PyString_FromStringAndSize(d_name, name_end - d_name - 1);
            }
            if (!name) {
                goto error;
            }
            /* make tuple (ino, name) */
            tuple = PyTuple_New(2);
            if (!tuple) {
                goto error;
            }
            PyTuple_SET_ITEM(tuple, 0, ino);
            PyTuple_SET_ITEM(tuple, 1, name);
            /* add entry */
            PyList_Append(list, tuple);
            /* dec */
            Py_DECREF(tuple);
        }
        else if (!entry && errno) {
            PyErr_SetFromErrno(PyExc_IOError);
            goto error;
        }
    } while(entry);

    rewinddir(dirp);
    if (closedir(dirp) == -1) {
        Py_DECREF(list);
        return PyErr_SetFromErrno(PyExc_IOError);
    }
    return list;
error:
    Py_XDECREF(list);
    Py_XDECREF(tuple);
    Py_XDECREF(ino);
    Py_XDECREF(name);
    rewinddir(dirp);
    if (closedir(dirp) == -1) {
        PyErr_Warn(PyExc_IOError, "Error: closedir() failed");
    }
    return NULL;
}


static PyMethodDef unistd_methods[] = {
    {"opendir", (PyCFunction)dirent_opendir, METH_KEYWORDS, dirent_opendir__doc__},
    {"readdir", (PyCFunction)dirent_readdir, METH_KEYWORDS, dirent_readdir__doc__},

    {NULL}
};


PyDoc_STRVAR(dirent__doc__, "");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initdirent(void)
{
    PyObject *m;

    m = Py_InitModule3("dirent", unistd_methods, dirent__doc__);

    if(m == NULL)
        return;
}
