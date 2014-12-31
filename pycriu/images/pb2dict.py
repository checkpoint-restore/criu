import google
import io

# pb2dict and dict2pb are using protobuf text format to
# convert protobuf msgs to/from dictionary.

def pb2dict(pb):
	"""
	Convert protobuf msg to dictionary.
	Takes a protobuf message and returns a dict.
	"""
	pb_text = io.BytesIO('')
	google.protobuf.text_format.PrintMessage(pb, pb_text)
	pb_text.seek(0)
	return _text2dict(pb_text)

def _text2dict(pb_text):
	"""
	Convert protobuf text format msg to dict
	Takes a protobuf message in text format and
	returns a dict.
	"""
	d = {}
	while True:
		s = pb_text.readline()
		s.strip()
		if s == '' or '}' in s:
			break

		name, value = s.split()
		if value == '{':
			value = _text2dict(pb_text)
		elif name.endswith(':'):
			name = name[:-1]
		else:
			raise Exception("Unknown format" + s)

		if d.get(name):
			if not isinstance(d[name], list):
				d[name] = [d[name]]
			d[name].append(value)
		else:
			d[name] = value

	return d

def dict2pb(d, pb):
	"""
	Convert dictionary to protobuf msg.
	Takes dict and protobuf message to be merged into.
	"""
	pb_text = io.BytesIO('')
	_dict2text(d, pb_text, 0)
	pb_text.seek(0)
	s = pb_text.read()
	google.protobuf.text_format.Merge(s, pb)

def _write_struct(name, text, indent, inside):
	"""
	Convert "inside" dict to protobuf text format
	wrap it inside block named "name" and write
	it to "text".
	"""
	text.write(indent*" " + name.encode() + " {\n")
	_dict2text(inside, text, indent+2)
	text.write(indent*" " + "}\n")

def _write_field(name, value, text, indent):
	"""
	Write "name: value" to "text".
	"""
	text.write(indent*" " + name.encode() + ": " + value.encode() + "\n")

def _dict2text(d, pb_text, indent):
	"""
	Convert dict to protobuf text format.
	Takes dict, protobuf message in text format and a number
	of spaces to be put before each field.
	"""
	for name, value in d.iteritems():
		if isinstance(value, unicode):
			_write_field(name, value, pb_text, indent)
		elif isinstance(value, list):
			for x in value:
				if isinstance(x, dict):
					_write_struct(name, pb_text, indent, x)
				else:
					_write_field(name, x, pb_text, indent)
		else:
			_write_struct(name, pb_text, indent, value)
