"""Small stable integration surface for the existing Python NOWAY Edge workspace."""

from pathlib import Path

from .engine import Controller, Engine
from .export import export_job
from .models import Config, Filter
from .store import Store


class EdgeFinder:
    def __init__(self, database: str | Path):
        self.store = Store(database)
        self.controller = Controller(self.store)

    def create(self, roots, **options) -> int:
        return Engine(self.store).create(Config(tuple(roots), **options))

    def start(self, job_id: int):
        self.controller.start(job_id)

    def pause(self):
        self.controller.pause()

    def stop(self):
        self.controller.pause(stop=True)

    def results(self, job_id: int, offset=0, limit=100, **filters):
        return self.store.page(job_id, Filter(**filters), offset, limit)

    def targets_for_scanner(self, job_id: int, output: str | Path, cdn_only=False) -> Path:
        """A plain hostname list consumable by Edge's existing TXT target importer."""
        return export_job(self.store, job_id, output, "txt", Filter(scope="in_scope", cdn_only=cdn_only))

    def export(self, job_id: int, output: str | Path, fmt="csv", **filters) -> Path:
        return export_job(self.store, job_id, output, fmt, Filter(**filters))

    async def run_async(self, job_id: int):
        if self.controller.active:
            raise ValueError("A background Finder job is already active")
        await Engine(self.store).run(job_id)

    def close(self):
        if self.controller.active:
            self.controller.pause(stop=True)
            self.controller.wait(10)
        self.store.close()
