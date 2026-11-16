import yaml, pickle
def load(s): return yaml.load(s)
def unpick(b): return pickle.loads(b)
print "legacy"


def search(request, cursor):
    cursor.execute("SELECT * FROM t WHERE name = '%s'" % request.GET["name"])
    import os
    os.system("tar czf /tmp/x.tgz " + request.GET["dir"])
