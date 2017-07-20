#include "block.h"
#include "main.h"

#include <cstdlib>

BlockFinder::BlockFinder()
    : cache(nullptr)
{}

static inline void UseIfCloser(CBlockIndex*& index, int height, CBlockIndex* ptr)
{
    if(ptr && abs(height-ptr->nHeight)<abs(index->nHeight-height))
        index=ptr;
}
    

CBlockIndex* BlockFinder::FindByHeight(int height)
{
    // If the height is at the bottom half of the chain, start searching from
    // the start to the end, otherwise search backwards from the end.
    // Brod: changed to one third. old blocks are less likely to be loaded
    if(!Best.top) return nullptr;
    CBlockIndex *index = height < Best.GetHeight() / 3
            ? pindexGenesisBlock
            : Best.top;

    //Brod: If the cached ptr is closed, use it
    UseIfCloser(index, height, cache);
    UseIfCloser(index, height, Best.p6m);
    UseIfCloser(index, height, Best.p14d);
            
    // Traverse towards the tail.
    while (index && index->HasPrev() && index->nHeight > height)
        index = index->GetPrev();
    
    // Traverse towards the head.
    while (index && index->HasNext() && index->nHeight < height)
        index = index->GetNext();
   
    cache = index;
    return index;  
}

void BlockFinder::Reset()
{
    cache = nullptr;
}
