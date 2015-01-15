from google.protobuf.descriptor import FieldDescriptor as FD

# pb2dict and dict2pb are methods to convert pb to/from dict.
# Inspired by:
#   protobuf-to-dict - https://github.com/benhodgson/protobuf-to-dict
#   protobuf-json    - https://code.google.com/p/protobuf-json/
#   protobuf source  - https://code.google.com/p/protobuf/
# Both protobuf-to-dict/json do not fit here because of several reasons,
# here are some of them:
#   - both have a common bug in treating optional field with empty
#     repeated inside.
#   - protobuf-to-json is not avalible in pip or in any other python
#     repo, so it is hard to distribute and we can't rely on it.
#   - both do not treat enums in a way we would like to. They convert
#     protobuf enum to int, but we need a string here, because it is
#     much more informative. BTW, protobuf text_format converts pb
#     enums to string value too. (i.e. "march : x86_64" is better then
#     "march : 1").


_basic_cast = {
	FD.TYPE_DOUBLE		: float,
	FD.TYPE_FLOAT		: float,
	FD.TYPE_FIXED64		: float,
	FD.TYPE_FIXED32		: float,
	FD.TYPE_SFIXED64	: float,
	FD.TYPE_SFIXED32	: float,

	FD.TYPE_INT64		: long,
	FD.TYPE_UINT64		: long,
	FD.TYPE_SINT64		: long,

	FD.TYPE_INT32		: int,
	FD.TYPE_UINT32		: int,
	FD.TYPE_SINT32		: int,

	FD.TYPE_BOOL		: bool,

	FD.TYPE_STRING		: unicode
}

def _pb2dict_cast(field, value):
	if field.type == FD.TYPE_MESSAGE:
		return pb2dict(value)
	elif field.type == FD.TYPE_BYTES:
		return value.encode('base64')
	elif field.type == FD.TYPE_ENUM:
		return field.enum_type.values_by_number.get(value, None).name
	elif field.type in _basic_cast:
		return _basic_cast[field.type](value)
	else:
		raise Exception("Field(%s) has unsupported type %d" % (field.name, field.type))

def pb2dict(pb):
	"""
	Convert protobuf msg to dictionary.
	Takes a protobuf message and returns a dict.
	"""
	d = {}
	for field, value in pb.ListFields():
		if field.label == FD.LABEL_REPEATED:
			d_val = []
			for v in value:
				d_val.append(_pb2dict_cast(field, v))
		else:
			d_val = _pb2dict_cast(field, value)

		d[field.name] = d_val
	return d

def _dict2pb_cast(field, value):
	# Not considering TYPE_MESSAGE here, as repeated
	# and non-repeated messages need special treatment
	# in this case, and are hadled separately.
	if field.type == FD.TYPE_BYTES:
		return value.decode('base64')
	elif field.type == FD.TYPE_ENUM:
		return field.enum_type.values_by_name.get(value, None).number
	else:
		return _basic_cast[field.type](value)

def dict2pb(d, pb):
	"""
	Convert dictionary to protobuf msg.
	Takes dict and protobuf message to be merged into.
	"""
	for field in pb.DESCRIPTOR.fields:
		if field.name not in d:
			continue
		value = d[field.name]
		if field.label == FD.LABEL_REPEATED:
			pb_val = getattr(pb, field.name, None)
			for v in value:
				if field.type == FD.TYPE_MESSAGE:
					dict2pb(v, pb_val.add())
				else:
					pb_val.append(_dict2pb_cast(field, v))
		else:
			if field.type == FD.TYPE_MESSAGE:
				# SetInParent method acts just like has_* = true in C,
				# and helps to properly treat cases when we have optional
				# field with empty repeated inside.
				getattr(pb, field.name).SetInParent()

				dict2pb(value, getattr(pb, field.name, None))
			else:
				setattr(pb, field.name, _dict2pb_cast(field, value))
	return pb
