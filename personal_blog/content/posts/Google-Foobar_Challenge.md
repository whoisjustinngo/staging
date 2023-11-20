+++
title = 'Google Foobar_Challenge'
date = 2023-11-02T21:08:35+08:00
draft = true
tags = []
+++

## Thought Process

The question is pretty straightforward - it wants us to sum up some terms in a sequence. But solving it efficiently isn’t that straightforward, and they already let you know off the bat that a brute force approach wouldn’t be good enough.

I took their hint to focus on what I didn’t have. My initial approach was to subtract the elements which I didn’t have from some value to get the sum the question is interested in. I tried writing scripts to generate the relevant sequence (the one we are trying to sum up) and to find the integers not in the relevant sequence, but I couldn’t find any discernible pattern which could help.

To be honest, I had to get a lot of help from resources online. The following is an explanation of how I eventually solved the question, in my own words.

I did some googling and realised that the relevant sequence is called a Beatty sequence. A Beatty sequence is a sequence of elements found by taking the floor of the positive multiples of a positive irrational number. Let us refer to the ‘positive irrational number’ of a Beatty sequence as $\alpha$, and use $B(\alpha)$ to represent a Beatty sequence with a particular $\alpha$.

[Beatty's/Rayleigh's theorem](https://proofwiki.org/wiki/Beatty%27s_Theorem#Source_of_Name) states that if $\alpha$ and $\beta$ are irrational numbers greater than 1, and $1/\alpha + 1/\beta = 1$, then $B(\alpha)$ and $B(\beta)$ are complementary sequences, i.e. they partition the natural numbers, i.e. every natural number belongs to exactly one of these sequences.

It would be useful to express beta in terms of alpha for later. We can simply rewrite the equation in the paragraph above to get:

**Theorem 1**
$$\beta = \frac{\alpha}{\alpha - 1} $$

<!-- Rayleigh's theorem is incredibly useful for our purposes. Given $m$, a natural number, and $\alpha$, an irrational number greater than 1, we can be certain that all the natural numbers between 1 and $m$ inclusive are either in $B(\alpha)$ or its complement $B(\beta)$. Since the sum of the natural numbers up to and including $m$ is easy to calculate, if we know the sum of all elements from 1 to $m$ inclusive which belong to a particular Beatty sequence, we can subtract this from the former to get the sum of all elements between 1 and $m$ inclusive which belong to the complementary Beatty sequence. -->

Since we are concerned with finite Beatty sequences, let us define:

$$
 (\alpha,n) = \lfloor 1 * \alpha \rfloor, \lfloor 2 * \alpha \rfloor, \lfloor 3 * \alpha \rfloor, ..., \lfloor n * \alpha \rfloor
$$

$$
S(\alpha,n) = \lfloor 1 * \alpha \rfloor + \lfloor 2 * \alpha \rfloor + \lfloor 3 * \alpha \rfloor + ... + \lfloor n * \alpha \rfloor
$$

The final term in $(\alpha, n)$ is $\lfloor n * \alpha \rfloor$. Let this be m. From Beatty's theorem, we know that every natural number between 1 and $m$ inclusive is either in $B(\alpha)$ or $B(\beta)$, its complement. Let the finite Beatty sequence containing all and only the elements from 1 to $m$ inclusive not in $(\alpha, n)$ be $(\beta, n')$.

Let us try to express $n'$ in terms of $n$ and $\alpha$. I have looked at multiple sources but my understanding of the math here is still pretty shallow so please bear with me. Since we know that the final term of $(\beta, n')$, which is $\lfloor n' * \beta \rfloor$, necessarily needs to be smaller than $m = \lfloor \alpha * n \rfloor$, we have the inequality $ \lfloor \beta \* n'\rfloor < m$ which becomes $n'\lfloor \beta\rfloor < m $, and then $n' < m / \lfloor \beta\rfloor$. Since $n'$ has to be a natural number and as large as possible to fully account for all the natural numbers in the range,

**Theorem 2**

$$
n' = \lfloor\frac{m}{\lfloor}\rfloor
$$

n' = floor(m / floor(beta)), which is the largest integer smaller than m / floor(beta).

... we can further express n' in terms of alpha and n.

As previously mentioned, (alpha, n) and (beta, n') partition the natural numbers from 1 to m = floor(alpha \* n) inclusive. Therefore, we can have

sum(1 to m) = S(alpha, n) + S(beta, n')
S(alpha, n) = sum(1 to m) - S(beta, n') = m(m + 1) / 2 - S(beta, floor(m / floor(beta))) =

---

In this case, we are interested in S(root(2), s) for some integer s given. But let us continue in general terms for the time being.
, and the number of elements to generate in the sequence as $n$. Since we are interested here in summing up the elements in a Beatty sequence, let us use (alpha, n) to denote the Beatty sequence formed by taking the floor of the multiples of the first n positive integers with alpha, and let us use S(alpha,n) to denote its sum. i.e.:
