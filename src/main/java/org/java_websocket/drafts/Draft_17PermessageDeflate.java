package org.java_websocket.drafts;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;

import java.util.Collections;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import org.java_websocket.exceptions.InvalidDataException;
import org.java_websocket.exceptions.InvalidFrameException;
import org.java_websocket.exceptions.InvalidHandshakeException;
import org.java_websocket.exceptions.LimitExedeedException;
import org.java_websocket.exceptions.NotSendableException;
import org.java_websocket.framing.CloseFrameBuilder;
import org.java_websocket.framing.FrameBuilder;
import org.java_websocket.framing.Framedata;
import org.java_websocket.framing.Framedata.Opcode;
import org.java_websocket.framing.FramedataImpl1;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.handshake.ClientHandshakeBuilder;
import org.java_websocket.handshake.HandshakeBuilder;
import org.java_websocket.handshake.ServerHandshakeBuilder;
import org.java_websocket.util.ByteAccumulator;
import org.java_websocket.util.Charsetfunctions;

public class Draft_17PermessageDeflate extends Draft_10 {
    private Deflater deflaterImpl;
    private Inflater inflaterImpl;
    private final static boolean NOWRAP = true;
    protected static final byte[] TAIL_BYTES = new byte[] { 0x00, 0x00, (byte)0xFF, (byte)0xFF };
    protected static final ByteBuffer TAIL_BYTES_BUF = ByteBuffer.wrap(TAIL_BYTES);
    
	@Override
	public HandshakeState acceptHandshakeAsServer( ClientHandshake handshakedata ) throws InvalidHandshakeException {
		int v = readVersion( handshakedata );
		if( handshakedata.getFieldValue( "Sec-WebSocket-Extensions" ).contains( "permessage-deflate" ) && v == 13 )
			return HandshakeState.MATCHED;
		return HandshakeState.NOT_MATCHED;
	}
	
	@Override
	public Framedata translateSingleFrame( ByteBuffer buffer ) throws IncompleteException , InvalidDataException {
		int maxpacketsize = buffer.remaining();
		boolean rsv1 = false;
		int realpacketsize = 2;
		if( maxpacketsize < realpacketsize )
			throw new IncompleteException( realpacketsize );
		byte b1 = buffer.get( /*0*/);
		boolean FIN = b1 >> 8 != 0;
		if ((b1 & 0x40) != 0)
        {
			rsv1 = true;
        }
        if ((b1 & 0x20) != 0)
        {
            throw new InvalidFrameException("RSV2 not allowed to be set");   
        }
        if ((b1 & 0x10) != 0)
        {
            throw new InvalidFrameException("RSV3 not allowed to be set");   
        }
		byte b2 = buffer.get( /*1*/);
		boolean MASK = ( b2 & -128 ) != 0;
		int payloadlength = (byte) ( b2 & ~(byte) 128 );
		Opcode optcode = toOpcode( (byte)(b1 & 0x0F) );

		if( !FIN ) {
			if( optcode == Opcode.PING || optcode == Opcode.PONG || optcode == Opcode.CLOSING ) {
				throw new InvalidFrameException( "control frames may no be fragmented" );
			}
		}

		if( payloadlength >= 0 && payloadlength <= 125 ) {
		} else {
			if( optcode == Opcode.PING || optcode == Opcode.PONG || optcode == Opcode.CLOSING ) {
				throw new InvalidFrameException( "more than 125 octets" );
			}
			if( payloadlength == 126 ) {
				realpacketsize += 2; // additional length bytes
				if( maxpacketsize < realpacketsize )
					throw new IncompleteException( realpacketsize );
				byte[] sizebytes = new byte[ 3 ];
				sizebytes[ 1 ] = buffer.get( /*1 + 1*/);
				sizebytes[ 2 ] = buffer.get( /*1 + 2*/);
				payloadlength = new BigInteger( sizebytes ).intValue();
			} else {
				realpacketsize += 8; // additional length bytes
				if( maxpacketsize < realpacketsize )
					throw new IncompleteException( realpacketsize );
				byte[] bytes = new byte[ 8 ];
				for( int i = 0 ; i < 8 ; i++ ) {
					bytes[ i ] = buffer.get( /*1 + i*/);
				}
				long length = new BigInteger( bytes ).longValue();
				if( length > Integer.MAX_VALUE ) {
					throw new LimitExedeedException( "Payloadsize is to big..." );
				} else {
					payloadlength = (int) length;
				}
			}
		}

		// int maskskeystart = foff + realpacketsize;
		realpacketsize += ( MASK ? 4 : 0 );
		// int payloadstart = foff + realpacketsize;
		realpacketsize += payloadlength;

		if( maxpacketsize < realpacketsize )
			throw new IncompleteException( realpacketsize );

		ByteBuffer payload = ByteBuffer.allocate( checkAlloc( payloadlength + 4 ) );
		if( MASK ) {
			byte[] maskskey = new byte[ 4 ];
			buffer.get( maskskey );
			for( int i = 0 ; i < payloadlength ; i++ ) {
				payload.put( (byte) ( (byte) buffer.get( /*payloadstart + i*/) ^ (byte) maskskey[ i % 4 ] ) );
			}
		} else {
			payload.put( buffer.array(), buffer.position(), payload.limit() );
			buffer.position( buffer.position() + payload.limit() );
		}

		FrameBuilder frame;
		if( optcode == Opcode.CLOSING ) {
			frame = new CloseFrameBuilder();
		} else {
			frame = new FramedataImpl1();
			frame.setFin( FIN );
			frame.setRsv1( rsv1 );
			frame.setOptcode( optcode );
		}
		if(frame.isRsv1() && optcode != Opcode.CLOSING && optcode != Opcode.PING && optcode != Opcode.PONG){
			Inflater inflater = getInflater();
			ByteAccumulator accumulator = newByteAccumulator();
			payload.put(TAIL_BYTES_BUF.slice());
			payload.flip();
			byte[] output = new byte[ 8192 ];
	        try {
		        while(payload.hasRemaining() && inflater.needsInput())
		        {
		        	if (!supplyInput(inflater,payload))
		            {
		                
		            }
		        	int read = 0;
		
						while ((read = inflater.inflate(output)) >= 0)
						{
						    if (read == 0)
						    {
						        break;
						    }
						    else
						    {
						    	accumulator.copyChunk(output,0,read);
						    }
						}        	
		        }
	        } catch (DataFormatException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			ByteBuffer deflated = ByteBuffer.allocate( accumulator.getLength() );
	        accumulator.transferTo(deflated);
	        frame.setPayload(deflated);
	         
		}else{
			payload.flip();
			frame.setPayload( payload );
		}
		return frame;
	}
	
	@Override
	public HandshakeBuilder postProcessHandshakeResponseAsServer( ClientHandshake request, ServerHandshakeBuilder response ) throws InvalidHandshakeException {
		response.put( "Upgrade", "websocket" );
		response.put( "Connection", request.getFieldValue( "Connection" ) ); // to respond to a Connection keep alives
		response.setHttpStatusMessage( "Switching Protocols" );
		String seckey = request.getFieldValue( "Sec-WebSocket-Key" );
		if( seckey == null )
			throw new InvalidHandshakeException( "missing Sec-WebSocket-Key" );
		response.put( "Sec-WebSocket-Accept", generateFinalKey( seckey ) );
		response.put( "Sec-WebSocket-Extensions", "permessage-deflate" );
		return response;
	}
	
	@Override
	public ClientHandshakeBuilder postProcessHandshakeRequestAsClient( ClientHandshakeBuilder request ) {
		super.postProcessHandshakeRequestAsClient( request );
		request.put( "Sec-WebSocket-Version", "13" );// overwriting the previous
		request.put( "Sec-WebSocket-Extensions", "permessage-deflate" );// overwriting the previous:"permessage-deflate"
		return request;
	}

	@Override
	public Draft copyInstance() {
		return new Draft_17PermessageDeflate();
	}
	
	@Override
	public List<Framedata> createFrames( ByteBuffer binary, boolean mask ) {
		FrameBuilder curframe = new FramedataImpl1();
		ByteBuffer payload = compress(binary);
		payload.limit(payload.limit() - TAIL_BYTES.length);
		try {
			curframe.setPayload( payload );
		} catch ( InvalidDataException e ) {
			throw new NotSendableException( e );
		}
		curframe.setFin( true );
		curframe.setRsv1( true );
		curframe.setOptcode( Opcode.BINARY );
		curframe.setTransferemasked( mask );
		return Collections.singletonList( (Framedata) curframe );
	}

	@Override
	public List<Framedata> createFrames( String text, boolean mask ) {
		ByteBuffer payload = compress(ByteBuffer.wrap( Charsetfunctions.utf8Bytes( text ) ));
		FrameBuilder curframe = new FramedataImpl1();
		payload.limit(payload.limit() - TAIL_BYTES.length);
		try {
			curframe.setPayload(payload );
		} catch ( InvalidDataException e ) {
			throw new NotSendableException( e );
		}
		curframe.setFin( true );
		curframe.setRsv1( true );
		curframe.setOptcode( Opcode.TEXT );
		curframe.setTransferemasked( mask );
		return Collections.singletonList( (Framedata) curframe );
	}
	
	private Opcode toOpcode( byte opcode ) throws InvalidFrameException {
		switch ( opcode ) {
			case 0:
				return Opcode.CONTINUOUS;
			case 1:
				return Opcode.TEXT;
			case 2:
				return Opcode.BINARY;
				// 3-7 are not yet defined
			case 8:
				return Opcode.CLOSING;
			case 9:
				return Opcode.PING;
			case 10:
				return Opcode.PONG;
				// 11-15 are not yet defined
			default :
				throw new InvalidFrameException( "unknow optcode " + (short) opcode );
		}
	}
	
	private ByteBuffer compress(ByteBuffer data){
		 boolean needsCompress = true;
		 int outputLength = Math.max(256,data.remaining());
         Deflater deflater = getDeflater();

         if (deflater.needsInput() && !supplyInput(deflater,data))
         {
             // no input supplied
             needsCompress = false;
         }
         
         ByteArrayOutputStream out = new ByteArrayOutputStream();

         byte[] output = new byte[outputLength];

         // Compress the data
         while (needsCompress)
         {
             int compressed = deflater.deflate(output,0,outputLength,Deflater.SYNC_FLUSH);
             out.write(output,0,compressed);

             if (compressed < outputLength)
             {
                 needsCompress = false;
             }
         }

         ByteBuffer payload = ByteBuffer.wrap(out.toByteArray());
         return payload;
	}
	
	public Deflater getDeflater()
    {
        if (deflaterImpl == null)
        {
            deflaterImpl = new Deflater(Deflater.DEFAULT_COMPRESSION,NOWRAP);
        }
        return deflaterImpl;
    }

    public Inflater getInflater()
    {
        if (inflaterImpl == null)
        {
            inflaterImpl = new Inflater(NOWRAP);
        }
        return inflaterImpl;
    }
    
    protected ByteAccumulator newByteAccumulator()
    {
        int maxSize = Integer.MAX_VALUE;
        return new ByteAccumulator(maxSize);
    }
    
    private static boolean supplyInput(Inflater inflater, ByteBuffer buf)
    {
        if (buf.remaining() <= 0)
        {
            return false;
        }

        byte input[];
        int inputOffset = 0;
        int len;

        if (buf.hasArray())
        {
            // no need to create a new byte buffer, just return this one.
            len = buf.remaining();
            input = buf.array();
            inputOffset = buf.position() + buf.arrayOffset();
            buf.position(buf.position() + len);
        }
        else
        {
            // Only create an return byte buffer that is reasonable in size
            len = Math.min(8192,buf.remaining());
            input = new byte[len];
            inputOffset = 0;
            buf.get(input,0,len);
        }

        inflater.setInput(input,inputOffset,len);
        return true;
    }
    
    private static boolean supplyInput(Deflater deflater, ByteBuffer buf)
    {
        if (buf.remaining() <= 0)
        {
            return false;
        }

        byte input[];
        int inputOffset = 0;
        int len;

        if (buf.hasArray())
        {
            // no need to create a new byte buffer, just return this one.
            len = buf.remaining();
            input = buf.array();
            inputOffset = buf.position() + buf.arrayOffset();
            buf.position(buf.position() + len);
        }
        else
        {
            // Only create an return byte buffer that is reasonable in size
            len = Math.min(8192,buf.remaining());
            input = new byte[len];
            inputOffset = 0;
            buf.get(input,0,len);
        }

        deflater.setInput(input,inputOffset,len);
        return true;
    }

}
