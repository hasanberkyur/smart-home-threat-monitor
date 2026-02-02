SEVERITY:
medium

SUMMARY:
Network telemetry indicates legitimate local activity where the IoT camera is streaming video data to the iPhone. The iPhone is simultaneously generating normal background WAN traffic to various cloud services. Although a destination IP address (172.236.213.46) listed in the camera's blacklist was detected on the network, the flow data attributes all WAN activity to the iPhone. This suggests the phone's camera management app is communicating with vendor infrastructure (which is allowed), while the camera itself remains successfully isolated from the internet.

EVIDENCE:
Strong local traffic flows (Ports 9000, 62238, 62240) between Camera (192.168.X.123) and iPhone (192.168.X.135) confirm active internal video streaming.
No outbound WAN connections originated from the Camera; the allow_wan=false policy is being respected.
All observed WAN traffic is attributed to the iPhone contacting reputable services (Apple, Cloudflare, Google).
The appearance of the blacklisted IP in "new_public_dests" correlates with the iPhone's activity and does not indicate a breach of the camera's isolation policy.

RECOMMENDED ACTION:
No action required; the observed patterns are consistent with normal device usage and effective network segmentation.