#!/usr/bin/python
# encoding=UTF-8
import os
import sys
import struct

OK = 0
ERR = 1
HEADER = b"HISEEAT\x00"
ADDR_BUFFER_ENABLE = "#define FEATURE_HAT_ADDR_BY_BUFFER"


def gen_path(chip_name, func_obj):
    script = os.path.abspath(sys.argv[0])
    pack_root = os.path.dirname(script)
    pack_name = os.path.basename(script).split('.')[0]
    paths = dict()
    paths["code"] = os.path.join(pack_root, 'config', pack_name + '.c')
    cfg_root = os.path.join(pack_root, 'config', pack_name + '.cfg')
    cfg_user = os.path.join(pack_root, 'config', chip_name, pack_name + '.cfg')
    paths["template"] = os.path.join(pack_root, 'framework', pack_name + '.c')
    if not os.path.isfile(cfg_root):
        print "ERR: func config not exist '%s'" % cfg_root
        return None

    if not os.path.isfile(paths["template"]):
        print "ERR: template not exist '%s'" % paths["template"]
        return None

    if isinstance(func_obj, list):
        del func_obj[:]
    elif isinstance(func_obj, dict):
        func_obj["list"] = ""
        func_obj['table'] = ""
        print '-------   function pack   -------'
    else:
        return paths

    counter = 0
    macros = list()
    for path in (cfg_root, cfg_user):
        if not os.path.isfile(path):
            continue
        fi = open(path, "r")
        line = fi.readline()
        while line:
            line = line.strip()
            if not line:
                if macros and isinstance(func_obj, dict):
                    macro = '#endif /* ' + macros.pop() + ' */\n'
                    func_obj['list'] += macro
                    func_obj['table'] += macro
            elif isinstance(func_obj, list):
                if '#' != line[0] and '/*' != line[0:2]:
                    func_obj.append(line)
            elif isinstance(func_obj, dict):
                if '/*' == line[0:2]:
                    func_obj['list'] += '\n' + line + '\n'
                    func_obj['table'] += '\n\t' + line + '\n'
                elif '#' == line[0]:
                    macro = ""
                    for item in line.strip('#').strip().split(' '):
                        if 3 > len(item):
                            continue
                        if item[0] in ('+', '-'):
                            if macro:
                                macro += ' && '
                            if  '-' == item[0]:
                                macro += '!'
                            macro += 'defined(' + item[1:] +  ')'
                    if macro:
                        macros.append(macro)
                        macro = '#if ' + macro + '\n'
                        func_obj['list'] += macro
                        func_obj['table'] += macro
                else:
                    counter += 1
                    func_obj['list'] += 'void %s(void);\n' % line
                    func_obj['table'] += '\t{(u32)%s, "%s"},\n' % (line, line)
                    print "    ---- pack func '" + line + "'"
            line = fi.readline()
        fi.close()
    if not isinstance(func_obj, list):
        print '------- function total = %d -------' % counter
    return paths


def gen_code(chip_name, use_map=True):
    # gen paths
    if isinstance(use_map, str) and use_map.isdigit():
        use_map = int(use_map)
    if not use_map:
        func_code = None
    else:
        func_code = dict()
    paths = gen_path(chip_name, func_code)
    if not paths:
        return ERR

    # gen c
    key_code = 'hat_object_s g_hat_sym_map[] = { };'
    if not use_map:
        insert_code = ADDR_BUFFER_DEFINE
    else:
        insert_code = func_code['list'] + key_code.replace('{ }', '{%s}' % func_code['table'])
    fi = open(paths["template"], "r")
    fo = open(paths["code"], "w")
    line = fi.readline()
    while line:
        if 0 <= line.find(key_code):
            line = insert_code
        fo.write(line)
        line = fi.readline()
    fi.close()
    fo.close()
    return OK


def remove_code(chip_name):
    # get function list
    func_list = list()
    paths = gen_path(chip_name, func_list)
    if not paths:
        return ERR

    os.remove(paths["code"])

    return OK

if __name__ == '__main__':
    if 2 > len(sys.argv):
        sys.exit(ERR)
    else:
        sys.exit(eval(sys.argv[1])(*sys.argv[2:]))
