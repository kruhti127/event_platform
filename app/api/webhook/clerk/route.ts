import { Webhook } from 'svix';
import { headers } from 'next/headers';
import { WebhookEvent } from '@clerk/nextjs/server';
import { createUser, deleteUser, updateUser } from '@/lib/actions/user.actions';
import { clerkClient } from '@clerk/nextjs';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  console.log('📨 Received Clerk webhook event');

  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    throw new Error('Missing WEBHOOK_SECRET in environment variables');
  }

  const headerPayload = headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    console.error('Missing SVIX headers');
    return new Response('Missing SVIX headers', { status: 400 });
  }

  const payload = await req.json();
  const body = JSON.stringify(payload);

  const wh = new Webhook(WEBHOOK_SECRET);

  let evt: WebhookEvent;

  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error('❌ Error verifying webhook:', err);
    return new Response('Invalid webhook signature', { status: 400 });
  }

  const eventType = evt.type;
  console.log('✅ Verified event type:', eventType);

  // Handle user.created
  if (eventType === 'user.created') {
    const { id, email_addresses, image_url, first_name, last_name, username } = evt.data;

    const user = {
      clerkId: id,
      email: email_addresses[0]?.email_address,
      username: username!,
      firstName: first_name,
      lastName: last_name,
      photo: image_url,
    };

    try {
      console.log('👤 Creating user:', user);

      const newUser = await createUser(user);

      if (newUser) {
        await clerkClient.users.updateUserMetadata(id, {
          publicMetadata: {
            userId: newUser._id,
          },
        });
      }

      return NextResponse.json({ message: 'User created', user: newUser });
    } catch (err) {
      console.error('❌ Error in user.created handler:', err);
      return new Response('Error creating user', { status: 500 });
    }
  }

  // Handle user.updated
  if (eventType === 'user.updated') {
    const { id, image_url, first_name, last_name, username } = evt.data;

    const updatedData = {
      firstName: first_name,
      lastName: last_name,
      username: username!,
      photo: image_url,
    };

    try {
      const updatedUser = await updateUser(id, updatedData);
      return NextResponse.json({ message: 'User updated', user: updatedUser });
    } catch (err) {
      console.error('❌ Error in user.updated handler:', err);
      return new Response('Error updating user', { status: 500 });
    }
  }

  // Handle user.deleted
  if (eventType === 'user.deleted') {
    const { id } = evt.data;

    try {
      const deletedUser = await deleteUser(id!);
      return NextResponse.json({ message: 'User deleted', user: deletedUser });
    } catch (err) {
      console.error('❌ Error in user.deleted handler:', err);
      return new Response('Error deleting user', { status: 500 });
    }
  }

  return new Response('Event ignored', { status: 200 });
}
