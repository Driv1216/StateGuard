from fastapi import FastAPI

app = FastAPI()


def helper(value):
    return value


def helper(value):  # noqa: F811
    return value


class Service:
    def grant(self):
        return True

    def run(self):
        return self.grant()


def outer(value):
    def nested(item):
        return item

    nested(value)
    return helper(value)


method_name = "run"
dynamic = getattr(Service(), method_name)
dynamic()
getattr(Service(), method_name)()
