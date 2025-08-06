/* eslint-disable camelcase */
import { clerkClient } from "@clerk/nextjs";
import { WebhookEvent } from "@clerk/nextjs/server";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { Webhook } from "svix";

import { createUser, deleteUser, updateUser } from "@/lib/actions/user.actions";

export async function POST(req) {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    console.error("Missing Clerk Webhook secret");
    return new Response("Server misconfiguration", { status: 500 });
  }

  // Get svix headers
  const headerPayload = headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Missing svix headers", { status: 400 });
  }

  // ✅ Get raw body (DO NOT use req.json())
  const body = await req.text();

  // Verify signature
  const wh = new Webhook(WEBHOOK_SECRET);
  let evt;

  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("Error verifying Clerk webhook:", err);
    return new Response("Invalid signature", { status: 400 });
  }

  // Get data + type
  const eventType = evt.type;
  const data = evt.data;

  try {
    // ✅ CREATE
    if (eventType === "user.created") {
      const { id, email_addresses, image_url, first_name, last_name, username } = data;

      const user = {
        clerkId: id,
        email: email_addresses?.[0]?.email_address ?? "",
        username: username ?? "",
        firstName: first_name ?? "",
        lastName: last_name ?? "",
        photo: image_url ?? "",
      };

      const newUser = await createUser(user);

      if (newUser) {
        await clerkClient.users.updateUserMetadata(id, {
          publicMetadata: { userId: newUser._id },
        });
      }

      return NextResponse.json({ message: "User created", user: newUser });
    }

    // ✅ UPDATE
    if (eventType === "user.updated") {
      const { id, image_url, first_name, last_name, username } = data;

      const user = {
        firstName: first_name ?? "",
        lastName: last_name ?? "",
        username: username ?? "",
        photo: image_url ?? "",
      };

      const updatedUser = await updateUser(id, user);

      return NextResponse.json({ message: "User updated", user: updatedUser });
    }

    // ✅ DELETE
    if (eventType === "user.deleted") {
      const { id } = data;

      const deletedUser = await deleteUser(id);

      return NextResponse.json({ message: "User deleted", user: deletedUser });
    }

    // ✅ For any unknown event, acknowledge
    console.log(`Unhandled Clerk event: ${eventType}`);
    return new Response("Event received", { status: 200 });

  } catch (error) {
    console.error(`Error handling Clerk event: ${eventType}`, error);
    return new Response("Webhook handler error", { status: 500 });
  }
}
