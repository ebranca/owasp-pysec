#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "structmember.h"

typedef struct {
    PyObject_HEAD
    
    PyObject**  elements;

    Py_ssize_t  length;
    Py_ssize_t  start;
    Py_ssize_t  end;
    Py_ssize_t  ins_length;   /* 1: delete 0: insert */
} Ring;

#define Ring_Check(obj) ((obj)->ob_type == &RingType)

static PyObject* Ring_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds);

PyDoc_STRVAR(Ring__doc__,
"Implementation of circular buffer.");

static int
Ring_init(Ring *self, PyObject *args, PyObject *kwds)
{
    Py_ssize_t length;
    
    static char *kwlist[] = {"length", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "n:Ring", kwlist, 
                                        &length))
        return -1;

    self->length = length;
    self->ins_length = 0;
    self->start = 0;
    self->end = 0;
    
    self->elements = PyMem_New(PyObject*, length);

    return 0;
}


PyDoc_STRVAR(Ring_push__doc__,
"Insert an object with associated key.");

static PyObject*
Ring_push(Ring *self, PyObject *o)
{
    int i;
    Py_ssize_t start;
    
    Py_INCREF(o);

    start = self->start;
    self->elements[start] = o;
    
    self->start = (start + 1) % self->length;

    if (self->ins_length < self->length)
        self->ins_length++;
    
    if (start == self->end && self->ins_length) {
        self->end = self->start;
    }

    Py_RETURN_NONE;
}


PyDoc_STRVAR(Ring_pop__doc__,
"REmove and return the last value.");

static PyObject*
Ring_pop(Ring *self) {
    PyObject *value;
    int b;

    if (!self->ins_length) {
        PyErr_SetString(PyExc_IndexError, "empty buffer");
        return NULL;
    }
    
    value = self->elements[self->end];

    self->end = (self->end + 1) % self->length;
    self->ins_length--;
    // DECREF

    return value;
}

static Py_ssize_t
Ring_len(PyObject *o)
{
    return ((Ring *)o)->ins_length;
}

PyDoc_STRVAR(Ring_max_length__doc__,
"Return the max length of the ring.");

static PyObject*
Ring_max_length(Ring *self)
{
    return PyInt_FromSsize_t(self->length);
}


static PySequenceMethods Ring_sequence = {
    Ring_len
};


static PyMethodDef Ring_methods[] = {
    {"push", (PyCFunction)Ring_push, METH_O, Ring_push__doc__},
    {"pop", (PyCFunction)Ring_pop, METH_NOARGS, Ring_pop__doc__},
    {"max", (PyCFunction)Ring_max_length, METH_NOARGS, Ring_max_length__doc__},
    { NULL }
};

static PyTypeObject RingType = {
    PyObject_HEAD_INIT(NULL)
    0,                              /* ob_size */
    "buffer.Ring",      /* tp_name */
    sizeof(Ring),          /* tp_basicsize */
    0,                              /* tp_itemsize */
    0,                              /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_compare */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    &Ring_sequence,        /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
      Py_TPFLAGS_BASETYPE,          /* tp_flags */
    Ring__doc__,           /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    Ring_methods,          /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    (initproc)Ring_init,   /* tp_init */
    0,                              /* tp_alloc */
    Ring_new,              /* tp_new */
};


static PyObject*
Ring_new(PyTypeObject *subtype, PyObject *args, PyObject *kwds)
{
    Ring *r;

    r = (Ring *)RingType.tp_alloc(&RingType, 0);
    return (PyObject *)r;
}


static PyMethodDef ring_methods[] = {
    { NULL }
};

PyDoc_STRVAR(ring__doc__,
"Implementation of Circular Buffer.");


#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initring(void)
{
    PyObject *m;
    
    RingType.tp_new = Ring_new;
    if (PyType_Ready(&RingType) < 0)
        return;

    m = Py_InitModule3("ring", ring_methods, ring__doc__);

    if(m == NULL)
        return;

    Py_INCREF(&RingType);
    PyModule_AddObject(m, "Ring", (PyObject *)&RingType);
}
