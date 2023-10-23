import logging
from threading import Thread

from attack import attack
from play import play, generate_address

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)

    a_addr = generate_address()
    # b_addr = ("127.0.0.2", generate_port())
    b_addr = generate_address()
    ab = Thread(target=play, args=[a_addr, b_addr], daemon=True, name="AB communicating")

    c = Thread(target=attack, args=[a_addr], daemon=True, name="C")
    c.start()
    ab.start()
    ab.join(50)
    c.join(50)
