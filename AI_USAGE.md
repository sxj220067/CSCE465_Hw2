# AI Usage for Homework 2

I used ChatGPT as a helper on September 30 and October 4, 2026.

## What AI helped with

AI helped me set up the Ubuntu environment and understand the crypto ideas when I got stuck.
It also helped me check code, fix errors, and think through the report.

## What I used it for

AI gave me ideas for the CTR attack, the handshake, and the secure record layer.
It also helped me write some Python code and test code, and it gave me suggestions for wording and formatting in the report.

I was still the one running the work in the VM and deciding what to keep.
AI was more like a side helper than the main author.

## What I changed myself

I entered the code and files into Ubuntu, fixed the command issues, and ran the actual demos and tests.
I also reviewed the report and edited the parts that needed to sound like my own work.

## How I checked it

I ran the tasks in the Ubuntu VM and captured the output.

- Task 1 showed the READ command turning into EDIT and the command being processed twice.
- Task 2 showed matching session keys and fresh keys in a second session.
- Task 3 showed normal communication and rejected modified, replayed, and reflected records.

The full test run reported 35 passing tests in 78.17 seconds.

## One thing to note

The IV format uses `session_id || sequence`, which can cause CTR counter overlap across longer records.
AI helped me notice this issue, and I included it in the report rather than treating it as a guarantee of security.


