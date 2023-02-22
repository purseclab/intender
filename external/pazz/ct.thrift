namespace java edu.purdue.cs.pursec.ifuzzer.searchservice
namespace py searchservice

/*
 C like comments are supported
*/
// This is also a valid comment

typedef i64 long
typedef i32 int // We can use typedef to get pretty names for the types we are using
service PathService
{
    list<string> findPaths(1:string dpid, 2:int egressPort, 3:string packetheader),
}
