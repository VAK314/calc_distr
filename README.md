# calc_distr
It is source code of distributed system with node CPU and GPU  which calculating chain of bitcoin private key -> public key -> private key... 
for example: there is a public key in the first line, but it is private key for second line etc 
000000008AB76E2A7C558FBFE6947A62A4F12484	111112w67YUUyvCNjcJcmsv6gHYHqMA6V
8bdcde11b113cb0d6d123cc3aabc761107c104e8  1DkXWof2gXWHJGdX7SfXBhvKuE5pyYFUJV
db76c181b630b68ba06dc97be1464425379c1dd8  1M1RFKEnDiPXDc77T9UNsaJJwXC8EvAMeA
8fbc5f17ffb104eeca0931cb85d809e3b258ae23  1E71HiCFJJgtzKP6kvqUQmCqCqufEQbjC9
Nodes send their results (only keys which begin "000000") to the server application then server application save their in data base (MySQL).
