import json

def byteify(inp):
    if isinstance(inp, dict):
        return {byteify(key):byteify(value) for key,value in inp.iteritems()}
    elif isinstance(inp, list):
        return [byteify(element) for element in inp]
    elif isinstance(inp, unicode):
        return inp.encode('utf-8')
    else:
        return inp

def apply_options(inp, options):
    if isinstance(inp, dict):
        return {apply_options(key, options):apply_options(value, options) for key,value in inp.iteritems()}
    elif isinstance(inp, list):
        return [apply_options(element, options) for element in inp]
    elif isinstance(inp, str):
        for (key, value) in options:
            s = "${%s}" % key
            inp = inp.replace(s, value)
        return inp
    else:
        return inp

class Config(dict):
    def read_from_file(self, config_file, options):
        config_json = open(config_file).read()
        config = byteify(json.loads(config_json))
        config = apply_options(config, options)
        self.update(config)

    def read_info_file(self, info_file):
        try:
            info = open(info_file, 'r')
        except:
            return False
        for line in info.readlines():
            key, val = map(str.strip, line.split("="))
            if key == "port":
                self["partov_server"][key] = int(val)
            elif key != "node":
                self["partov_server"][key] = val
        return True

config = Config()
