def get_fd_usage():
    with open('/proc/sys/fs/file-nr', 'rb') as fnr:
        line = fnr.readline()
        fields = line.strip().split()
        if len(fields) != 3:
            raise OSError("wrong format of '/proc/sys/fs/file-nr'")
        return tuple(fields)
