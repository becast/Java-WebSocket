package org.java_websocket.util;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class ByteAccumulator
{
private final List<byte[]> chunks = new ArrayList<>();
private final int maxSize;
private int length = 0;

public ByteAccumulator(int maxOverallBufferSize)
{
    this.maxSize = maxOverallBufferSize;
}

public void copyChunk(byte buf[], int offset, int length)
{
    if (this.length + length > maxSize)
    {

    }

    byte copy[] = new byte[length - offset];
    System.arraycopy(buf,offset,copy,0,length);

    chunks.add(copy);
    this.length += length;
}

public int getLength()
{
    return length;
}

public void transferTo(ByteBuffer buffer)
{
    if (buffer.remaining() < length)
    {
        throw new IllegalArgumentException(String.format("Not enough space in ByteBuffer remaining [%d] for accumulated buffers length [%d]",
                buffer.remaining(),length));
    }

    int position = buffer.position();
    for (byte[] chunk : chunks)
    {
        buffer.put(chunk,0,chunk.length);
    }
    buffer.flip();
    buffer.position(position);
}
}

