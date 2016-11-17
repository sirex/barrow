from wam import validate


def test_empty():
    import cerberus

    v = cerberus.Validator({'a': {
        'type': 'integer',
        'coerce': int,
        'default': 'a',
    }})
    r = v.validated({})
    print(v.errors)
    assert r == {}
