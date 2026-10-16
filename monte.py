from random import randint

from Crypto.Util.number import getPrime


def random_votes(m: int, k: int) -> list[list[int]]:
    votes: list[list[int]] = []

    for _ in range(m):
        vote: list[int] = [0] * k
        vote[randint(0, k-1)] = 1
        votes.append(vote)

    return votes


def tally_votes(votes: list[list[int]], k: int) -> list[int]:
    tally: list[int] = [0] * k

    for vote in votes:
        for i in range(k):
            tally[i] += vote[i]

    return tally


def vote_percentages(tally: list[int], m: int, k: int) -> list[float]:
    percentages: list[float] = [tally[i] / m for i in range(k)]

    return percentages


def ss_split_vote(vote: list[int], n: int, k: int, q: int) -> list[list[int]]:
    shares: list[list[int]] = []

    for _ in range(n-1):
        share: list[int] = [randint(0, q-1) for _ in range(k)]
        shares.append(share)

    share: list[int] = [0] * k
    for i in range(k):
        share[i] = vote[i]
        for j in range(n-1):
            share[i] -= shares[j][i]
        share[i] = share[i] % q

    shares.append(share)

    return shares


def ss_open_tally(tallies: list[list[int]], n: int, k: int, q: int) -> list[int]:
    tally: list[int] = [0] * k

    for i in range(k):
        c: int = 0
        for j in range(n):
            c += tallies[j][i] % q

        tally[i] = c % q

    return tally


N = 3
M = 100
K = 3

print(f"{N=}, {M=}, {K=}")

# Generate the votes
votes = random_votes(M, K)

# Calculate ideal world
print("--- IDEAL WORLD")

ideal_tally = tally_votes(votes, K)
print(f"Ideal world tally: {ideal_tally}")

ideal_percentage = vote_percentages(ideal_tally, M, K)
print(f"Ideal world percentages: {ideal_percentage}")

# Calculate MPC
print("--- MPC")

q = getPrime(256)
print(f"{q=}")

split_votes = [ss_split_vote(vote, N, K, q) for vote in votes]

mpc_tallies: list[list[int]] = []

for i in range(N):
    node_votes = [split_votes[j][i] for j in range(M)]
    node_tally = tally_votes(node_votes, K)
    print(f"Node Tally for {i=}: {node_tally}")
    mpc_tallies.append(node_tally)

mpc_tally = ss_open_tally(mpc_tallies, N, K, q)

print(f"MPC Tally: {mpc_tally}")
