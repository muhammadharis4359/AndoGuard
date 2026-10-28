"""Tests for BackendExecutor concurrency and thread affinity."""

import concurrent.futures
import threading
import time

import pytest

from andoguard.adapters.backend import BackendExecutor
from andoguard.errors import BackendError


def test_executor_basic_execution() -> None:
    executor = BackendExecutor(thread_name="Test-Worker-Basic")
    try:

        def add(a: int, b: int) -> int:
            return a + b

        result = executor.submit(add, 5, 7)
        assert result == 12
    finally:
        executor.shutdown()


def test_executor_exception_propagation() -> None:
    executor = BackendExecutor(thread_name="Test-Worker-Exc")
    try:

        def failing_task() -> None:
            raise ValueError("Something went wrong in parser")

        with pytest.raises(BackendError) as exc_info:
            executor.submit(failing_task)
        assert "Something went wrong in parser" in str(exc_info.value)
    finally:
        executor.shutdown()


def test_executor_same_thread_avoid_deadlock() -> None:
    executor = BackendExecutor(thread_name="Test-Worker-Deadlock")
    try:

        def nested_task() -> str:
            # When already on the owner thread, submit should execute inline
            assert executor.is_owner_thread()
            return "executed_inline"

        def outer_task() -> str:
            return executor.submit(nested_task)

        res = executor.submit(outer_task)
        assert res == "executed_inline"
    finally:
        executor.shutdown()


def test_executor_concurrency_stress_eight_threads() -> None:
    """Stress test: 8 concurrent caller threads submitting jobs to the single worker thread.

    Verifies:
    1. All 8 threads complete without race conditions or deadlocks.
    2. All jobs are executed strictly on the single dedicated owner thread.
    """
    executor = BackendExecutor(thread_name="AndoGuard-StressWorker")
    num_threads = 8
    tasks_per_thread = 10

    worker_thread_ids: set[int] = set()
    lock = threading.Lock()

    def work_item(thread_idx: int, task_idx: int) -> tuple[int, int, int]:
        current_thread = threading.get_ident()
        with lock:
            worker_thread_ids.add(current_thread)
        # Small sleep to simulate parsing latency
        time.sleep(0.005)
        return (thread_idx, task_idx, current_thread)

    def thread_runner(t_id: int) -> list[tuple[int, int, int]]:
        results = []
        for i in range(tasks_per_thread):
            res = executor.submit(work_item, t_id, i)
            results.append(res)
        return results

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(thread_runner, t) for t in range(num_threads)]
            all_results = []
            for f in concurrent.futures.as_completed(futures):
                all_results.extend(f.result())

        assert len(all_results) == num_threads * tasks_per_thread
        # Crucial check: all tasks must have executed on EXACTLY ONE owner worker thread
        assert len(worker_thread_ids) == 1, (
            f"Expected 1 owner thread, got {len(worker_thread_ids)}"
        )
    finally:
        executor.shutdown()
