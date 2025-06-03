import os
import json

import requests


class Validate:

    def __init__(self, manifest: str = "manifest.json") -> None:
        if not os.path.exists(manifest):
            raise ValueError(f"manifest.json '{manifest}' doesn't exist.")
        self.manifest = manifest

    def run(self) -> bool:
        data: dict = {}
        with open(self.manifest) as f:
            data = json.load(f)
        for item in data.get("lists"):
            if item.get("file") and not os.path.exists(item["file"]):
                raise ValueError(f"referenced static file does not exist: '{item}'")
            elif item.get("url"):
                resp = requests.request("GET", item["url"])
                resp.raise_for_status()
                if not resp.ok:
                    raise requests.exceptions.HTTPError(f"unable to retrieve file from URL: '{item['url']}'")


if __name__ == "__main__":
    Validate().run()
