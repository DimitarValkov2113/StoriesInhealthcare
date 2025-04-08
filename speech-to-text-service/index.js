require('dotenv').config();
const express = require('express');
const cors = require('cors');
const {
  TranscribeStreamingClient,
  StartStreamTranscriptionCommand,
} = require('@aws-sdk/client-transcribe-streaming');
const WebSocket = require('ws');
const winston = require('winston');

// Constants
const HTTP_PORT = process.env.PORT || 3005;
const WS_PORT = process.env.WS_PORT || 8080;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const SAMPLE_RATE = 16000;
const SILENCE_BUFFER_SIZE = 8192;
const STREAM_DELAY_MS = 250;

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'transcription-service.log' }),
  ],
});

// Custom Error Classes
class TranscriptionError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'TranscriptionError';
    this.status = 500;
    this.cause = cause;
  }
}

class WebSocketError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'WebSocketError';
    this.status = 500;
    this.cause = cause;
  }
}

// Dependency Injection
const createTranscribeClient = (config = {}) => {
  return new TranscribeStreamingClient({
    region: config.region || AWS_REGION,
    credentials: {
      accessKeyId: config.accessKeyId || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
    },
  });
};

const createWebSocketServer = (port = WS_PORT) => {
  const wss = new WebSocket.Server({ port });
  wss.binaryType = 'arraybuffer';
  return wss;
};

// Audio Stream Generator
async function* audioStreamGenerator(audioQueue) {
  while (true) {
    if (audioQueue.length > 0) {
      const chunk = audioQueue.shift();
      if (chunk.length === 0) {
        logger.info('End of audio stream detected');
        return;
      }
      logger.debug('Sending audio chunk to AWS', { size: chunk.length });
      yield { AudioEvent: { AudioChunk: Buffer.from(chunk) } };
      await new Promise((resolve) => setTimeout(resolve, STREAM_DELAY_MS));
    } else {
      logger.debug('Waiting for more audio or stop signal');
      await new Promise((resolve) => setTimeout(resolve, STREAM_DELAY_MS));
      if (audioQueue.length === 0) {
        logger.info('Sending final silence buffer');
        yield { AudioEvent: { AudioChunk: Buffer.alloc(SILENCE_BUFFER_SIZE, 0) } };
        await new Promise((resolve) => setTimeout(resolve, STREAM_DELAY_MS * 2));
        if (audioQueue.length === 0) return;
      }
    }
  }
}

// Transcription Service
const transcriptionService = (transcribeClient) => ({
  /**
   * Starts real-time transcription for a WebSocket client.
   * @param {WebSocket} ws - The WebSocket connection.
   * @param {Buffer[]} audioQueue - Queue of audio chunks.
   * @returns {Promise<void>}
   */
  startRealTimeTranscription: async (ws, audioQueue) => {
    logger.info('Starting transcription process');
    const command = new StartStreamTranscriptionCommand({
      LanguageCode: 'en-US',
      MediaSampleRateHertz: SAMPLE_RATE,
      MediaEncoding: 'pcm',
      AudioStream: audioStreamGenerator(audioQueue),
    });

    try {
      const response = await transcribeClient.send(command);
      logger.info('Transcription request sent to AWS');

      for await (const event of response.TranscriptResultStream) {
        logger.debug('Received AWS event', { event: JSON.stringify(event) });
        if (event.TranscriptEvent) {
          const results = event.TranscriptEvent.Transcript.Results;
          if (results.length > 0 && results[0].Alternatives.length > 0) {
            const transcribedText = results[0].Alternatives[0].Transcript;
            logger.info('Transcribed text', { text: transcribedText });
            ws.send(JSON.stringify({ transcribedText }));
          } else {
            logger.debug('No transcription in this event');
          }
        }
      }
    } catch (error) {
      logger.error('Transcription error', { error });
      throw new TranscriptionError('Failed to process transcription', error);
    }
  },
});

// WebSocket Handler
const webSocketHandler = (wss, transcriptionService) => {
  wss.on('connection', (ws) => {
    logger.info('Client connected to WebSocket');
    const audioQueue = [];
    let isProcessing = false;

    ws.on('message', async (message) => {
      try {
        if (Buffer.isBuffer(message)) {
          if (message.length > 100) {
            logger.debug('Received audio chunk', { size: message.length });
            audioQueue.push(message);
            if (!isProcessing) {
              isProcessing = true;
              await transcriptionService.startRealTimeTranscription(ws, audioQueue)
                .catch((error) => {
                  ws.send(JSON.stringify({ error: error.message }));
                })
                .finally(() => {
                  isProcessing = false;
                });
            }
          } else {
            const msgStr = message.toString();
            try {
              const data = JSON.parse(msgStr);
              if (data.action === 'stop') {
                logger.info('Stopping transcription');
                await new Promise((resolve) => setTimeout(resolve, 500));
                audioQueue.push(Buffer.alloc(0));
              }
            } catch (err) {
              logger.debug('Small buffer not JSON, treating as audio', { size: message.length });
              audioQueue.push(message);
            }
          }
        }
      } catch (error) {
        logger.error('WebSocket message handling error', { error });
        ws.send(JSON.stringify({ error: 'Message processing failed' }));
      }
    });

    ws.on('close', () => {
      logger.info('Client disconnected from WebSocket');
      audioQueue.length = 0;
      isProcessing = false;
    });

    ws.on('error', (error) => {
      logger.error('WebSocket error', { error });
      throw new WebSocketError('WebSocket connection error', error);
    });
  });
};

// Route Handlers
const createRoutes = () => {
  const router = express.Router();

  /**
   * Health check endpoint to verify service status.
   * @route GET /health
   * @returns {object} - Status message and timestamp.
   */
  router.get('/health', (req, res) => {
    const status = {
      status: 'Transcription Service is running',
      httpPort: HTTP_PORT,
      wsPort: WS_PORT,
      timestamp: new Date().toISOString(),
    };
    logger.info('Health check requested', { status });
    res.json(status);
  });

  return router;
};

// Application Setup
const initializeApp = ({
  transcribeClient = createTranscribeClient(),
  wsServer = createWebSocketServer(),
} = {}) => {
  const app = express();
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
  app.use('/api', createRoutes()); // Mount routes under /api

  const transcribeService = transcriptionService(transcribeClient);
  webSocketHandler(wsServer, transcribeService);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(HTTP_PORT, () => {
    logger.info(`HTTP Server running on port ${HTTP_PORT}`);
    logger.info(`WebSocket Server running on port ${WS_PORT}`);
  });
};

// Graceful Shutdown
const shutdown = () => {
  logger.info('Shutting down Transcription Service');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

module.exports = { initializeApp, transcriptionService, audioStreamGenerator }; // For testing