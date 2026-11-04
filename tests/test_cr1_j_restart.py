"""Independent-process task durability and SQLite crash rollback."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

from sentinel.storage.connection import database_connection
from sentinel.tasks import (
    TaskStatus,
    TaskStoreErrorCode,
    create_local_task,
    list_local_tasks,
    setup_local_task_operator,
)
from tests.test_cr1_j_support import initialized_task_database


def test_committed_task_is_recovered_by_a_fresh_python_process(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "restart-task.sqlite3")
    setup_local_task_operator(database)
    created = create_local_task(database, request_id=uuid4(), title="Survives process exit").task
    script = (
        "import json,sys; from pathlib import Path; from sentinel.tasks import list_local_tasks; "
        "tasks=list_local_tasks(Path(sys.argv[1])); "
        "print(json.dumps([[str(t.task_id),t.title,t.status.value,t.revision] for t in tasks]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(database)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=12,
        check=False,
        env=os.environ.copy(),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [[str(created.task_id), "Survives process exit", "OPEN", 1]]


def test_process_death_before_commit_rolls_back_task_and_request_receipt(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "crash-before-commit.sqlite3")
    setup_local_task_operator(database)
    request_id = uuid4()
    script = "\n".join(
        (
            "import os, sys",
            "from pathlib import Path",
            "from uuid import UUID",
            "import sentinel.tasks.store as store",
            "store._insert_creation_receipt = lambda *_args: os._exit(86)",
            "store.create_local_task(",
            "    Path(sys.argv[1]), request_id=UUID(sys.argv[2]), title='crash task'",
            ")",
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(database),
            str(request_id),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=12,
        check=False,
        env=os.environ.copy(),
    )
    assert result.returncode == 86
    assert list_local_tasks(database) == ()
    with database_connection(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM task_creation_requests").fetchone() == (0,)


def test_two_processes_cannot_both_update_the_same_revision(tmp_path: Path) -> None:
    database = initialized_task_database(tmp_path / "concurrent-edit.sqlite3")
    setup_local_task_operator(database)
    task = create_local_task(database, request_id=uuid4(), title="Concurrent edit").task
    gate = tmp_path / "start-editers"
    script = "\n".join(
        (
            "import sys, time",
            "from pathlib import Path",
            "from uuid import UUID",
            "from sentinel.tasks import edit_local_task, TaskStoreError, TaskStoreErrorCode",
            "db = Path(sys.argv[1])",
            "task = UUID(sys.argv[2])",
            "ready = Path(sys.argv[3])",
            "gate = Path(sys.argv[4])",
            "title = sys.argv[5]",
            "ready.write_text('ready', encoding='ascii')",
            "deadline = time.monotonic() + 5",
            "while not gate.exists() and time.monotonic() < deadline:",
            "    time.sleep(0.005)",
            "if not gate.exists(): raise SystemExit(9)",
            "for _ in range(100):",
            "    try:",
            "        edit_local_task(db, task_id=task, expected_revision=1, title=title)",
            "    except TaskStoreError as error:",
            "        if error.code is TaskStoreErrorCode.WRITER_UNAVAILABLE:",
            "            time.sleep(0.01)",
            "            continue",
            "        print(error.code.value)",
            "        raise SystemExit(0)",
            "    else:",
            "        print('updated')",
            "        raise SystemExit(0)",
            "raise SystemExit(10)",
        )
    )
    processes: list[subprocess.Popen[str]] = []
    outputs: list[str] = []
    try:
        for index, title in enumerate(("edit one", "edit two")):
            ready = tmp_path / f"ready-{index}"
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(database),
                        str(task.task_id),
                        str(ready),
                        str(gate),
                        title,
                    ],
                    cwd=tmp_path,
                    env=os.environ.copy(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not all(
            (tmp_path / f"ready-{index}").exists() for index in range(2)
        ):
            time.sleep(0.01)
        assert all((tmp_path / f"ready-{index}").exists() for index in range(2))
        gate.write_text("go", encoding="ascii")
        for process in processes:
            stdout, stderr = process.communicate(timeout=12)
            assert process.returncode == 0, stderr
            assert stderr == ""
            outputs.append(stdout.strip())
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)

    assert outputs.count("updated") == 1
    assert (
        outputs.count(TaskStoreErrorCode.REVISION_CONFLICT.value)
        + outputs.count(TaskStoreErrorCode.WRITER_UNAVAILABLE.value)
        == 1
    )
    tasks = list_local_tasks(database)
    assert len(tasks) == 1 and tasks[0].revision == 2
    assert tasks[0].status is TaskStatus.OPEN
