import { errorResponse, jsonResponse } from '../utils/response';

// The notification center and the event upload of the official clients.
//
// NodeWarden keeps no end-user notifications: the list is always empty and no
// notification id is ever found. Organizations answer `useEvents: false`, so
// the clients do not record events; an upload that arrives anyway is
// accepted and dropped, as vaultwarden does while organization events are off.
// A refused upload would only make the client keep the events and retry.

/** GET /api/notifications */
export function handleListNotifications(): Response {
  return jsonResponse({ data: [], object: 'list', continuationToken: null });
}

/** PATCH /api/notifications/:id/read and DELETE /api/notifications/:id/delete */
export function handleNotificationNotFound(): Response {
  return errorResponse('Notification not found.', 404);
}

/** POST /events/collect */
export function handleCollectEvents(): Response {
  return new Response(null, { status: 200 });
}
