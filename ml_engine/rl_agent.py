import random
import logging
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RLAgent:
    def __init__(self, actions=None):
        self.actions = actions if actions else ["increase_length", "change_char", "add_nop_sled"]
        self.q_table = {} # State -> Action values
        self.learning_rate = 0.1
        self.discount_factor = 0.95
        self.epsilon = 0.1 # Exploration rate

    def get_state(self, last_response_code, payload_length):
        """
        Discretize state space.
        """
        return (last_response_code, payload_length // 10) # Bucketize length

    def choose_action(self, state):
        if random.uniform(0, 1) < self.epsilon:
            return random.choice(self.actions)
        
        if state not in self.q_table:
            self.q_table[state] = np.zeros(len(self.actions))
        
        return self.actions[np.argmax(self.q_table[state])]

    def learn(self, state, action_idx, reward, next_state):
        if state not in self.q_table:
            self.q_table[state] = np.zeros(len(self.actions))
        if next_state not in self.q_table:
            self.q_table[next_state] = np.zeros(len(self.actions))
            
        prediction = self.q_table[state][action_idx]
        target = reward + self.discount_factor * np.max(self.q_table[next_state])
        self.q_table[state][action_idx] = prediction + self.learning_rate * (target - prediction)

    def optimize_exploit(self, initial_payload, iterations=50, target_ip=None, target_port=None):
        """
        Runs an RL loop to optimize the payload.
        """
        logger.info("Starting RL optimization...")
        
        # Ensure payload is bytes
        if isinstance(initial_payload, str):
            current_payload = initial_payload.encode()
        else:
            current_payload = initial_payload
            
        # Use Fuzzer for sending payloads
        from ml_engine.fuzzing_module import Fuzzer
        fuzzer = Fuzzer(target_ip, target_port)
        
        for i in range(iterations):
            state = self.get_state(200, len(current_payload))
            action = self.choose_action(state)
            action_idx = self.actions.index(action)
            
            # Apply action
            if action == "increase_length":
                current_payload += b"A" * 10
            elif action == "change_char":
                # Replace last byte
                if len(current_payload) > 0:
                    current_payload = current_payload[:-1] + b"B"
            elif action == "add_nop_sled":
                current_payload = b"\x90" * 10 + current_payload
            
            # Get Reward (Real or Mock)
            reward = 0
            is_crash = False
            
            if target_ip:
                # Real Attack
                is_crash = fuzzer.send_payload(current_payload)
                if is_crash:
                    reward = 100
                    logger.info(f"RL Agent: CRASH achieved at iteration {i}!")
                else:
                    reward = -1 # Alive (Penalty for failure)
            else:
                # Mock Reward
                if len(current_payload) > 200: 
                    reward = 10
                    is_crash = True
            
            next_state = self.get_state(500 if is_crash else 200, len(current_payload))
            self.learn(state, action_idx, reward, next_state)
            
            if is_crash:
                break
            
        return current_payload

if __name__ == "__main__":
    agent = RLAgent()
    print(f"Optimized Payload: {agent.optimize_exploit('start')}")
