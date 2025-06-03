import os
import json

import requests


class Validate:

    def __init__(self, manifest: str = "manifest.json") -> None:
        if not os.path.exists(manifest):
            err = f"manifest.json '{manifest}' doesn't exist."
            self.set_output("error", err)
            raise ValueError(err)
        self.manifest = manifest

    def set_output(self, name, value):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            print(f'{name}={value}', file=fh)

    def run(self) -> bool:
        data: dict = {}
        with open(self.manifest) as f:
            data = json.load(f)
        for item in data.get("lists"):
            if item.get("file") and not os.path.exists(item["file"]):
                err = f"referenced static file does not exist: '{item}'"
                self.set_output("error", err)
                raise ValueError(err)
            elif item.get("url"):
                resp = requests.request("GET", item["url"])
                resp.raise_for_status()
                if not resp.ok:
                    err = f"unable to retrieve file from URL: '{item['url']}'"
                    self.set_output("error", err)
                    raise requests.exceptions.HTTPError(err)


if __name__ == "__main__":
    Validate().run()
