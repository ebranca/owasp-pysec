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

#include "Python.h"
#include "structseq.h"

#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/un.h>
#include <linux/if.h>
#include <limits.h>
#include <string.h>


PyDoc_STRVAR(AddressIn__doc__,
"");

static PyTypeObject AddressIn = {0, 0, 0, 0, 0, 0};

static PyStructSequence_Field AddressIn_fields[] = {
    {"family", "Socket family"},
    {"address", "IPv4 address"},
    {"port", "Port number"},
    {NULL}
};

static PyStructSequence_Desc AddressIn_desc = {
    "AddressIn",
    AddressIn__doc__,
    AddressIn_fields,
    3
};

#define PyAddressIn_Check(op)   (Py_TYPE(op) == &AddressIn)


PyDoc_STRVAR(AddressIn6__doc__,
"");

static PyTypeObject AddressIn6 = {0, 0, 0, 0, 0, 0};

static PyStructSequence_Field AddressIn6_fields[] = {
    {"family", "Socket family"},
    {"address", "IPv6 address"},
    {"port", "Port number"},
    {"flowinfo", "IPv6 flow info"},
    {"scope_id", "Scope ID"},
    {NULL}
};

static PyStructSequence_Desc AddressIn6_desc = {
    "AddressIn6",
    AddressIn6__doc__,
    AddressIn6_fields,
    5
};

#define PyAddressIn6_Check(op)   (Py_TYPE(op) == &AddressIn6)

PyDoc_STRVAR(AddressUn__doc__,
"");

static PyTypeObject AddressUn = {0, 0, 0, 0, 0, 0};

static PyStructSequence_Field AddressUn_fields[] = {
    {"family", "Socket family"},
    {"path", "Pathname"},
    {NULL}
};

static PyStructSequence_Desc AddressUn_desc = {
    "AddressUn",
    AddressUn__doc__,
    AddressUn_fields,
    2
};

#define PyAddressUn_Check(op)   (Py_TYPE(op) == &AddressUn)

static PyObject*
sockaddr_storage2addr_ss(struct sockaddr_storage *addr)
{
    struct sockaddr *sa;
    struct sockaddr_in *ain;
    struct sockaddr_in6 *ain6;
    struct sockaddr_un *aun;
    PyObject *addr_struct, *tmp;
    sa = (struct sockaddr *)addr;
    switch (sa->sa_family)
    {
        case AF_INET:
            ain = (struct sockaddr_in *)addr;
            if ((addr_struct = PyStructSequence_New(&AddressIn)) == NULL)
                goto error;
            if ((tmp = PyInt_FromLong(ain->sin_family)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 0, tmp);
            if ((tmp = PyInt_FromLong(ntohs(ain->sin_port))) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 1, tmp);
            if ((tmp = PyInt_FromLong(ntohl(ain->sin_addr.s_addr))) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 2, tmp);
            break;
        case AF_INET6:
            ain6 = (struct sockaddr_in6 *)addr;
            if ((addr_struct = PyStructSequence_New(&AddressIn6)) == NULL)
                goto error;
            if ((tmp = PyInt_FromLong(ain6->sin6_family)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 0, tmp);
            if ((tmp = PyInt_FromLong(htons(ain6->sin6_port))) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 1, tmp);
            if ((tmp = PyInt_FromLong(ain6->sin6_flowinfo)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 2, tmp);

            if ((tmp = PyString_FromStringAndSize((char *)ain6->sin6_addr.s6_addr, 16)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 3, tmp);

            if ((tmp = PyInt_FromLong(ain6->sin6_scope_id)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 4, tmp);
            break;
        case AF_UNIX:
            aun = (struct sockaddr_un *)addr;
            if ((addr_struct = PyStructSequence_New(&AddressUn)) == NULL)
                goto error;
            if ((tmp = PyInt_FromLong(aun->sun_family)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 2, tmp);
            // TODO - from string min(len(path), UNIX_PATH_MAX)
            if ((tmp = PyString_FromStringAndSize((char *)aun->sun_path, UNIX_PATH_MAX)) == NULL)
                goto error;
            PyStructSequence_SET_ITEM(addr_struct, 2, tmp);
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "unknown socket family");
            goto error;
    }
    return addr_struct;
error:
    Py_XDECREF(addr_struct);
    Py_XDECREF(tmp);
    return NULL;
}


#define PyStructSequence_GetItem(op, i)  (((PyStructSequence *)(op))->ob_item[i])

static struct sockaddr_storage*
addr_ss2sockaddr_storage(PyObject *addr_struct, socklen_t *addr_len)
{
    if (PyAddressIn_Check(addr_struct)) {
        struct sockaddr_in *sin;
        uint32_t family, address, pport;
        uint16_t port;

        sin = (struct sockaddr_in *)PyMem_New(struct sockaddr_storage, 1);
        if (sin == NULL) {
            PyErr_NoMemory();
            return NULL;
        }

        family = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 0));
        if (family == -1 && PyErr_Occurred())
            return NULL;
        if (family != AF_INET) {
            PyErr_SetString(PyExc_ValueError, "wrong family, need AF_INET");
            return NULL;
        }

        address = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 1));
        if (address == -1 && PyErr_Occurred())
            return NULL;
        
        pport = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 2));
        if(pport == -1 && PyErr_Occurred())
            return NULL;
        if (pport > 65535) {
            PyErr_SetString(PyExc_ValueError, "port number too big [0-65535]");
            return NULL;
        }
        port = (uint16_t)pport;

        sin->sin_family = family;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = htonl(address);

        if (addr_len != NULL)
            *addr_len = sizeof(struct sockaddr_in);

        return (struct sockaddr_storage *)sin; 
    }
    else if (PyAddressIn6_Check(addr_struct)) {
        struct sockaddr_in6 *sin6;
        uint32_t family,flowinfo, scope_id, pport;
        uint16_t port;
        Py_ssize_t _addr_len;
        uint8_t *address;

        sin6 = (struct sockaddr_in6 *)PyMem_New(struct sockaddr_storage, 1);
        if (sin6 == NULL) {
            PyErr_NoMemory();
            return NULL;
        }

        family = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 0));
        if (family == -1 && PyErr_Occurred())
            return NULL;
        if (family != AF_INET6) {
            PyErr_SetString(PyExc_ValueError, "wrong family, need AF_INET6");
            return NULL;
        }

        pport = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 2));
        if (pport == -1 && PyErr_Occurred())
            return NULL;
        if (pport > 65535) {
            PyErr_SetString(PyExc_ValueError, "port number too big [0-65535]");
            return NULL;
        }
        port = (uint16_t)pport;

        flowinfo = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 3));
        if (flowinfo == -1 && PyErr_Occurred())
            return NULL;

        scope_id = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 4));
        if (scope_id == -1 && PyErr_Occurred())
            return NULL;

        if(PyString_AsStringAndSize(PyStructSequence_GetItem(addr_struct, 1), (char **)&address, &_addr_len) == -1)
            return NULL;
        if (_addr_len != 16) {
            PyErr_SetString(PyExc_ValueError, "IPv6 address must be 16 chars long");
            return NULL;
        }

        sin6->sin6_family = family;
        sin6->sin6_port = htonl(port);
        sin6->sin6_flowinfo = flowinfo;
        memcpy(sin6->sin6_addr.s6_addr, address, 16);
        sin6->sin6_scope_id = scope_id;

        if (addr_len != NULL)
            *addr_len = sizeof(struct sockaddr_in6);

        return (struct sockaddr_storage *)sin6; 
    }
    else if (PyAddressUn_Check(addr_struct)) {
        struct sockaddr_un *sun;
        int family;
        char *path;
        Py_ssize_t path_len;

        sun = (struct sockaddr_un *)PyMem_New(struct sockaddr_storage, 1);
        if (sun == NULL) {
            PyErr_NoMemory();
            return NULL;
        }

        family = PyInt_AsUnsignedLongMask(PyStructSequence_GetItem(addr_struct, 0));
        if (family == -1 && PyErr_Occurred())
            return NULL;
        if (family != AF_UNIX) {
            PyErr_SetString(PyExc_ValueError, "wrong family, need AF_UNIX");
            return NULL;
        }

        if(PyString_AsStringAndSize(PyStructSequence_GetItem(addr_struct, 1), &path, &path_len) == -1)
            return NULL;
        if (path_len == 0) {
            PyErr_SetString(PyExc_ValueError, "path cannot be empty");
            return NULL;
        }
        if (path_len > UNIX_PATH_MAX-1) {
            PyErr_SetString(PyExc_ValueError, "path too long");
            return NULL;
        }

        sun->sun_family = family;
        memset(sun->sun_path, 0, UNIX_PATH_MAX);
        memcpy(sun->sun_path, path, path_len);

        if (addr_len != NULL)
            *addr_len = sizeof(struct sockaddr_un);

        return (struct sockaddr_storage *)sun;
    }
    else {
        PyErr_SetString(PyExc_TypeError, "needs address struct sequences");
        return NULL;
    }
}



PyDoc_STRVAR(socket_socket__doc__,
"");
/* TODO - doc */

static PyObject*
socket_socket(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, domain, type, protocol;
    static char *kwlist[] = {"domain", "type", "protocol", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iii:socket", kwlist, &domain, &type, &protocol)) {
        return NULL;
    }

    fd = socket(domain, type, protocol);
    if (fd < 0)
        return PyErr_SetFromErrno(PyExc_OSError);
 
    return PyInt_FromLong(fd);
}

PyDoc_STRVAR(socket_accept__doc__,
"");

static PyObject*
socket_accept(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, conn_fd;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    PyObject *conn, *addr_struct, *res;
    static char *kwlist[] = {"fd", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i:accept", kwlist, &fd)) {
        return NULL;
    }

    addr_len = sizeof(struct sockaddr_storage);
    conn_fd = accept(fd, (struct sockaddr *)&addr, &addr_len);

    if (conn_fd == -1)
        return PyErr_SetFromErrno(PyExc_OSError);

    res = PyTuple_New(2);
    if (res == NULL)
        goto error;
    Py_INCREF(res);
    addr_struct = sockaddr_storage2addr_ss(&addr);
    if (addr_struct == NULL)
        goto error;
    Py_INCREF(addr_struct);
    PyTuple_SET_ITEM(res, 1, addr_struct); 
    conn = PyInt_FromLong(conn_fd);
    if (conn == NULL)
        goto error;
    PyTuple_SET_ITEM(res, 0, conn); 
    return res;
error:
    Py_XDECREF(addr_struct);
    Py_XDECREF(conn);
    Py_XDECREF(res);
    return NULL;
}


PyDoc_STRVAR(socket_bind__doc__,
"");

static PyObject*
socket_bind(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, err;
    PyObject *addr_struct;
    struct sockaddr_storage *addr;
    socklen_t addr_len;
    static char *kwlist[] = {"fd", "addr", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iO:bind", kwlist, &fd, &addr_struct)) {
        return NULL;
    }
    addr = addr_ss2sockaddr_storage(addr_struct, &addr_len);
    if (addr == NULL)
        return NULL;

    err = bind(fd, (struct sockaddr *)addr, addr_len);

    if (err == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        PyMem_Free(addr);
        return NULL;
    }
    PyMem_Free(addr);
    Py_RETURN_NONE;
}


PyDoc_STRVAR(socket_connect__doc__,
"");

static PyObject*
socket_connect(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, err;
    PyObject *addr_struct;
    struct sockaddr_storage *addr;
    socklen_t addr_len;
    static char *kwlist[] = {"fd", "addr", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iO:connect", kwlist, &fd, &addr_struct)) {
        return NULL;
    }
    addr = addr_ss2sockaddr_storage(addr_struct, &addr_len);
    if (addr == NULL)
        return NULL;

    err = connect(fd, (struct sockaddr *)addr, addr_len);
    if (err == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        PyMem_Free(addr);
        return NULL;
    }
    PyMem_Free(addr);
    Py_RETURN_NONE;
}


PyDoc_STRVAR(socket_listen__doc__,
"");

static PyObject*
socket_listen(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, backlog, err;
    static char *kwlist[] = {"fd", "backlog", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ii:listen", kwlist, &fd, &backlog)) {
        return NULL;
    }

    err = listen(fd, backlog);
    if (err == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    Py_RETURN_NONE;
}


PyDoc_STRVAR(socket_recv__doc__,
"");

static PyObject*
socket_recv(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, flags;
    Py_ssize_t buf_len;
    size_t rd_len;
    void *buffer;
    PyObject *res;
    static char *kwlist[] = {"fd", "length", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ini:recv", kwlist, &fd, &buf_len, &flags)) {
        return NULL;
    }

    buffer = (void *)PyMem_New(uint8_t, buf_len);
    if (buffer == NULL)
        return PyErr_NoMemory();

    rd_len = recv(fd, buffer, buf_len, flags);
    if (rd_len == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        PyMem_Free(buffer);
        return NULL;
    }
    
    res = PyString_FromStringAndSize(buffer, rd_len);
    PyMem_Free(buffer);
    return res;
}


PyDoc_STRVAR(socket_recvfrom__doc__,
"");

static PyObject*
socket_recvfrom(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, flags;
    Py_ssize_t buf_len;
    size_t rd_len;
    void *buffer;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    PyObject *res, *msg, *addr_struct;
    static char *kwlist[] = {"fd", "length", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ini:recv", kwlist, &fd, &buf_len, &flags)) {
        return NULL;
    }

    buffer = (void *)PyMem_New(uint8_t, buf_len);
    if (buffer == NULL)
        return PyErr_NoMemory();

    addr_len = sizeof(struct sockaddr_storage);

    rd_len = recvfrom(fd, buffer, buf_len, flags, (struct sockaddr *)&addr, &addr_len);
    if (rd_len == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        PyMem_Free(buffer);
        return NULL;
    }
    
    msg = PyString_FromStringAndSize(buffer, rd_len);
    if (msg == NULL)
        goto error;
    PyMem_Free(buffer);
 
    res = PyTuple_New(2);
    if (res == NULL)
        goto error;
    Py_INCREF(res);

    PyTuple_SET_ITEM(res, 0, msg); 

    addr_struct = sockaddr_storage2addr_ss(&addr);
    if (addr_struct == NULL) {
        Py_INCREF(Py_None);
        addr_struct = Py_None;
    }
        
    Py_INCREF(addr_struct);
    PyTuple_SET_ITEM(res, 1, addr_struct); 
    return res;
error:
    Py_XDECREF(addr_struct);
    Py_XDECREF(msg);
    Py_XDECREF(res);
    return NULL;
}


PyDoc_STRVAR(socket_send__doc__,
"");

static PyObject*
socket_send(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, flags;
    Py_ssize_t buf_len, send_len;
    void *buffer;
    static char *kwlist[] = {"fd", "buffer", "flags", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "is#i:send", kwlist, &fd, &buffer, &buf_len, &flags)) {
        return NULL;
    }

    send_len = send(fd, buffer, buf_len, flags);
    if (send_len == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyInt_FromSsize_t(send_len);
}


PyDoc_STRVAR(socket_sendto__doc__,
"");

static PyObject*
socket_sendto(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, flags;
    Py_ssize_t buf_len, send_len;
    void *buffer;
    struct sockaddr_storage *addr;
    socklen_t addr_len;
    PyObject *addr_struct;
    static char *kwlist[] = {"fd", "buffer", "flags", "to", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "is#iO:sendto", kwlist, &fd, &buffer, &buf_len, &flags, &addr_struct)) {
        return NULL;
    }


    addr = addr_ss2sockaddr_storage(addr_struct, &addr_len);
    if (addr == NULL)
        return NULL;

    send_len = sendto(fd, buffer, buf_len, flags, (struct sockaddr *)addr, addr_len);
    if (send_len == -1) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return PyInt_FromSsize_t(send_len);
}


PyDoc_STRVAR(socket_getsocksolopt__doc__,
"");

static PyObject*
socket_getsocksolopt(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, optname, optint;
    long long timeout;
    void *optvoid;
    socklen_t optlen;
    PyObject *res;

    optvoid = NULL;
    res = NULL;
 
    static char *kwlist[] = {"fd", "opt", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "ii:getsockopt", kwlist, &fd, &optname)) {
        return NULL;
    }
    switch(optname)
    {
        case SO_ACCEPTCONN:
        case SO_BROADCAST:
        case SO_DEBUG:
        case SO_DONTROUTE:
        case SO_REUSEADDR:
        case SO_KEEPALIVE:
        case SO_OOBINLINE:
            optlen = sizeof(optint);
            if (getsockopt(fd, SOL_SOCKET, optname, &optint, &optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            res = PyBool_FromLong(optint);
            break;
        case SO_BINDTODEVICE:
            optvoid = PyMem_New(char, IFNAMSIZ);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            optlen = IFNAMSIZ * sizeof(char);
            if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, optvoid, &optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            res = PyString_FromStringAndSize(optvoid, optlen);
            break;
        case SO_DOMAIN:
        case SO_ERROR:
        case SO_PROTOCOL:
        case SO_RCVBUF:
        case SO_RCVLOWAT:
        case SO_SNDBUF:
        case SO_SNDLOWAT:
        case SO_TYPE:
            optlen = sizeof(optint);
            if (getsockopt(fd, SOL_SOCKET, optname, &optint, &optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            res = PyInt_FromLong(optint);
            break;
        case SO_LINGER:
            optvoid = PyMem_New(struct linger, 1);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            optlen = sizeof(struct linger);
            if (getsockopt(fd, SOL_SOCKET, SO_LINGER, optvoid, &optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            if (((struct linger *)optvoid)->l_onoff)
                res = PyInt_FromLong(((struct linger *)optvoid)->l_linger);
            else
                res = Py_None;
            break;
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
            optvoid = PyMem_New(struct timeval, 1);
            optlen = sizeof(struct timeval);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            if (getsockopt(fd, SOL_SOCKET, optname, optvoid, &optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            timeout = ((struct timeval *)optvoid)->tv_sec * 1000000 + ((struct timeval *)optvoid)->tv_usec;
            res = PyLong_FromLongLong(timeout);
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "unknown option");
            goto error;
    }
    if (res == NULL)
        goto error;
    Py_INCREF(res);
    return res;
error:
    PyMem_Free(optvoid);
    Py_XDECREF(res);
    return NULL;
}

PyDoc_STRVAR(socket_setsocksolopt__doc__,
"");

static PyObject*
socket_setsocksolopt(PyObject* self, PyObject* args, PyObject* kwds)
{
    int fd, optname, optint;
    long ol;
    long long secs, usecs, timeout;
    void *optvoid;
    socklen_t optlen;
    PyObject *val;

    optvoid = NULL;
 
    static char *kwlist[] = {"fd", "opt", "val", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iiO:getsockopt", kwlist, &fd, &optname, &val)) {
        return NULL;
    }
    switch(optname)
    {
        case SO_ACCEPTCONN:
        case SO_DOMAIN:
        case SO_ERROR:
        case SO_PROTOCOL:
        case SO_TYPE:
            PyErr_SetString(PyExc_ValueError, "read-only option");
            goto error;
        case SO_BROADCAST:
        case SO_DEBUG:
        case SO_DONTROUTE:
        case SO_REUSEADDR:
        case SO_KEEPALIVE:
        case SO_OOBINLINE:
            optint = PyObject_IsTrue(val);
            if (optint == -1)
                goto error;
            optlen = sizeof(optint);
            if (setsockopt(fd, SOL_SOCKET, optname, &optint, optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            break;
        case SO_BINDTODEVICE:
            optvoid = PyMem_New(char, IFNAMSIZ);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            optlen = IFNAMSIZ * sizeof(char);
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, optvoid, optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            break;
        case SO_RCVBUF:
        case SO_RCVLOWAT:
        case SO_SNDBUF:
        case SO_SNDLOWAT:
            ol = PyInt_AsLong(val);
            if (ol == -1 && PyErr_Occurred())
                goto error;
            if (ol > INT_MAX) {
                PyErr_SetString(PyExc_ValueError, "too big value for interger option");
                goto error;
            }
            optint = (int)ol;
            optlen = sizeof(optint);
            if (setsockopt(fd, SOL_SOCKET, optname, &optint, optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            break;
        case SO_LINGER:
            optvoid = PyMem_New(struct linger, 1);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            optlen = sizeof(struct linger);
            if (val == Py_None) {
                ((struct linger *) optvoid)->l_onoff = 0;
                ((struct linger *) optvoid)->l_linger = 0;
            }
            else {
                ol = PyInt_AsLong(val);
                if (ol == -1 && PyErr_Occurred())
                    goto error;
                if (ol > INT_MAX) {
                    PyErr_SetString(PyExc_ValueError, "too big value for interger option");
                    goto error;
                }
                ((struct linger *) optvoid)->l_onoff = 1;
                ((struct linger *) optvoid)->l_linger = (int) ol;
            }
            if (setsockopt(fd, SOL_SOCKET, SO_LINGER, optvoid, optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            break;
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
            optvoid = PyMem_New(struct timeval, 1);
            optlen = sizeof(struct timeval);
            if (optvoid == NULL) {
                PyErr_NoMemory();
                goto error;
            }
            timeout = PyLong_AsLongLong(val);
            if (PyErr_Occurred())
                goto error;
            secs = timeout / 1000000;
            usecs = timeout % 1000000;
            if (secs > LONG_MAX) {
                PyErr_SetString(PyExc_ValueError, "too big value for timeout");
                goto error;
            }
            ((struct timeval *)optvoid)->tv_sec = secs;
            ((struct timeval *)optvoid)->tv_usec = usecs;
            if (setsockopt(fd, SOL_SOCKET, optname, optvoid, optlen) == -1) {
                PyErr_SetFromErrno(PyExc_OSError);
                goto error;
            }
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "unknown option");
            goto error;
    }
    Py_RETURN_NONE;
error:
    PyMem_Free(optvoid);
    return NULL;
}

static PyMethodDef socket_methods[] = {
    {"socket", (PyCFunction)socket_socket, METH_KEYWORDS, socket_socket__doc__},
    {"accept", (PyCFunction)socket_accept, METH_KEYWORDS, socket_accept__doc__},
    {"bind", (PyCFunction)socket_bind, METH_KEYWORDS, socket_bind__doc__},
    {"connect", (PyCFunction)socket_connect, METH_KEYWORDS, socket_connect__doc__},
    {"listen", (PyCFunction)socket_listen, METH_KEYWORDS, socket_listen__doc__},
    {"recv", (PyCFunction)socket_recv, METH_KEYWORDS, socket_recv__doc__},
    {"recvfrom", (PyCFunction)socket_recvfrom, METH_KEYWORDS, socket_recvfrom__doc__},
    {"send", (PyCFunction)socket_send, METH_KEYWORDS, socket_send__doc__},
    {"sendto", (PyCFunction)socket_sendto, METH_KEYWORDS, socket_sendto__doc__},
    {"getsocksolopt", (PyCFunction)socket_getsocksolopt, METH_KEYWORDS, socket_getsocksolopt__doc__},
    {"setsocksolopt", (PyCFunction)socket_setsocksolopt, METH_KEYWORDS, socket_setsocksolopt__doc__},
    {NULL}
};


PyDoc_STRVAR(socket__doc__, "");

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC
#endif
PyMODINIT_FUNC
initsocket(void)
{
    PyObject *m;

    m = Py_InitModule3("socket", socket_methods, socket__doc__);

    if (AddressIn.tp_name == 0)
        PyStructSequence_InitType(&AddressIn, &AddressIn_desc);
    Py_INCREF((PyObject *)&AddressIn);
    PyModule_AddObject(m, "AddressIn", (PyObject *)&AddressIn);

    if (AddressIn6.tp_name == 0)
        PyStructSequence_InitType(&AddressIn6, &AddressIn6_desc);
    Py_INCREF((PyObject *)&AddressIn6);
    PyModule_AddObject(m, "AddressIn6", (PyObject *)&AddressIn6);

    if (AddressUn.tp_name == 0)
        PyStructSequence_InitType(&AddressUn, &AddressUn_desc);
    Py_INCREF((PyObject *)&AddressUn);
    PyModule_AddObject(m, "AddressUnix", (PyObject *)&AddressUn);

    if (PyModule_AddIntMacro(m, SOCK_STREAM))
        return;
    if (PyModule_AddIntMacro(m, SOCK_DGRAM))
        return;
    if (PyModule_AddIntMacro(m, SOCK_SEQPACKET))
        return;
    if (PyModule_AddIntMacro(m, SOCK_RAW))
        return;
    if (PyModule_AddIntMacro(m, SOCK_RDM))
        return;
    
    if (PyModule_AddIntMacro(m, SOL_SOCKET))
        return;

    if (PyModule_AddIntMacro(m, SO_ACCEPTCONN))
        return;
    if (PyModule_AddIntMacro(m, SO_BINDTODEVICE))
        return;
    if (PyModule_AddIntMacro(m, SO_BROADCAST))
        return;
    if (PyModule_AddIntMacro(m, SO_DEBUG))
        return;
    if (PyModule_AddIntMacro(m, SO_DOMAIN))
        return;
    if (PyModule_AddIntMacro(m, SO_DONTROUTE))
        return;
    if (PyModule_AddIntMacro(m, SO_ERROR))
        return;
    if (PyModule_AddIntMacro(m, SO_KEEPALIVE))
        return;
    if (PyModule_AddIntMacro(m, SO_LINGER))
        return;
    if (PyModule_AddIntMacro(m, SO_OOBINLINE))
        return;
    if (PyModule_AddIntMacro(m, SO_PROTOCOL))
        return;
    if (PyModule_AddIntMacro(m, SO_REUSEADDR))
        return;
    if (PyModule_AddIntMacro(m, SO_RCVBUF))
        return;
    if (PyModule_AddIntMacro(m, SO_RCVLOWAT))
        return;
    if (PyModule_AddIntMacro(m, SO_RCVTIMEO))
        return;
    if (PyModule_AddIntMacro(m, SO_SNDBUF))
        return;
    if (PyModule_AddIntMacro(m, SO_SNDLOWAT))
        return;
    if (PyModule_AddIntMacro(m, SO_SNDTIMEO))
        return;
    if (PyModule_AddIntMacro(m, SO_TYPE))
        return;
    if (PyModule_AddIntMacro(m, SOMAXCONN))
        return;

    if (PyModule_AddIntMacro(m, MSG_CTRUNC))
        return;
    if (PyModule_AddIntMacro(m, MSG_DONTROUTE))
        return;
    if (PyModule_AddIntMacro(m, MSG_EOR))
        return;
    if (PyModule_AddIntMacro(m, MSG_OOB))
        return;
    if (PyModule_AddIntMacro(m, MSG_PEEK))
        return;
    if (PyModule_AddIntMacro(m, MSG_TRUNC))
        return;
    if (PyModule_AddIntMacro(m, MSG_WAITALL))
        return;

    if (PyModule_AddIntMacro(m, AF_INET))
        return;
    if (PyModule_AddIntMacro(m, AF_INET6))
        return;
    if (PyModule_AddIntMacro(m, AF_UNIX))
        return;
    if (PyModule_AddIntMacro(m, AF_IPX))
        return;
    if (PyModule_AddIntMacro(m, AF_NETLINK))
        return;
    if (PyModule_AddIntMacro(m, AF_X25))
        return;
    if (PyModule_AddIntMacro(m, AF_AX25))
        return;
    if (PyModule_AddIntMacro(m, AF_ATMPVC))
        return;
    if (PyModule_AddIntMacro(m, AF_APPLETALK))
       return; 
    if (PyModule_AddIntMacro(m, AF_PACKET))
        return;
    if (PyModule_AddIntMacro(m, AF_UNSPEC))
        return;

    if (PyModule_AddIntMacro(m, SHUT_RD))
        return;
    if (PyModule_AddIntMacro(m, SHUT_RDWR))
        return;
    if (PyModule_AddIntMacro(m, SHUT_WR))
        return;

    if(m == NULL)
        return;
}
