#!/usr/bin/env python3
"""
Example usage of the enhanced behavior agent.

This example shows how to use the new behavior agent interface.
Install dependencies first: pip install -r requirements.txt
"""

import asyncio
from agents.behavior_agent import analyze_behavior, create_email_store

async def example_usage():
    """Example of using the enhanced behavior agent."""
    
    # Create storage backend (SQLite or Redis)
    store = create_email_store("sqlite", db_path="data/email_behavior.db")
    
    # Example email data
    email_data = {
        "from": "Amazon Support <noreply@suspicious-domain.com>",
        "subject": "Urgent: Your account will be suspended!",
        "headers": {
            "Date": "Mon, 21 Oct 2024 11:00:00 +0000",
            "Reply-To": "different@another-domain.com",
            "Message-ID": "<12345@suspicious-domain.com>"
        },
        "body_text": "Please verify your account immediately or it will be suspended."
    }
    
    # Analyze behavior
    result = await analyze_behavior(email_data, store)
    
    print("📊 Behavior Analysis Results:")
    print(f"Score: {result['score']:.3f}")
    print(f"Details: {result['details']}")
    print(f"Reasons: {', '.join(result['reasons'])}")
    
    print(f"\n👤 Sender History:")
    history = result['sender_history']
    if history['is_new_sender']:
        print("Status: New sender (no prior messages)")
    else:
        print(f"Message Count: {history['message_count']}")
        print(f"First Seen: {history['first_seen']}")
        print(f"Last Seen: {history['last_seen']}")
    
    # Close storage
    await store.close()

if __name__ == "__main__":
    asyncio.run(example_usage())
