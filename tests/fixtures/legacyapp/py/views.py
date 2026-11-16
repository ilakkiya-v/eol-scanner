import yaml, pickle
def load(s): return yaml.load(s)
def unpick(b): return pickle.loads(b)
print "legacy"
