import type { ErrorRequestHandler, RequestHandler } from 'express';

export const notFoundHandler: RequestHandler = (_request, response) => {
  response.status(404).json({
    success: false,
    error: { code: 'NOT_FOUND', message: 'The requested resource was not found.' },
  });
};

export const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  const candidate = error !== null && typeof error === 'object'
    ? error as { status?: unknown; statusCode?: unknown }
    : {};
  const parserStatus = candidate.statusCode ?? candidate.status;
  const status = typeof parserStatus === 'number' && parserStatus >= 400 && parserStatus < 500
    ? parserStatus
    : 500;

  let code = 'INTERNAL_ERROR';
  let message = 'An unexpected error occurred.';
  if (status === 400) {
    code = 'INVALID_REQUEST';
    message = 'The request body is invalid.';
  } else if (status === 413) {
    code = 'REQUEST_TOO_LARGE';
    message = 'The request body exceeds the allowed size.';
  }

  response.status(status).json({ success: false, error: { code, message } });
};
